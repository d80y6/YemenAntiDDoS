//go:build linux

// AF_XDP zero-copy packet inspection sockets.
//
// The inline XDP program steers flagged L7 traffic (action "challenge" and
// optionally sampled flows) into the `xsight_xsk` XSKMAP; this file owns the
// userspace socket end: UMEM registration, ring plumbing and the RX loop
// that feeds payload slices into the L7 inspector.
//
// Layout follows uapi/linux/if_xdp.h (kernel 5.4+):
//
//	setsockopt(XDP_UMEM_REG / XDP_UMEM_FILL_RING / XDP_UMEM_COMPLETION_RING /
//	           XDP_RX_RING / XDP_TX_RING)
//	getsockopt(XDP_MMAP_OFFSETS) → ring producer/consumer/desc offsets
//	mmap(UMEM) + mmap(rings) → shared-memory descriptors (zero copy)

package bpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XDP socket setsockopt/getsockopt options (if_xdp.h).
const (
	xdpOptMmapOffsets = 1
	xdpOptUmemReg     = 4
	xdpOptFillRing    = 5
	xdpOptCompRing    = 6
	xdpOptTxRing      = 7
	xdpOptRxRing      = 8

	xdpSharedUmem       = 1
	xdpCopy             = 2
	xdpZerocopy         = 3
	xdpUmemUnalignedFlg = 1 << 3
)

// Default AF_XDP geometry.
const (
	DefaultUmemFrames = 4096
	DefaultFrameSize  = 4096
	DefaultFillRings  = 2048
	DefaultCompRings  = 2048
	DefaultHeadroom   = 0
	xskRingDescSize   = 16 // sizeof(struct xdp_desc)
)

// xdpRingOffset mirrors struct xdp_ring_offset.
type xdpRingOffset struct {
	Producer uint64
	Consumer uint64
	Desc     uint64
	Flags    uint64
}

// xdpMmapOffsets mirrors struct xdp_mmap_offsets.
type xdpMmapOffsets struct {
	RX   xdpRingOffset
	TX   xdpRingOffset
	Fill xdpRingOffset
	Comp xdpRingOffset
}

// xdpUmemReg mirrors struct xdp_umem_reg (5.4+ layout with flags+pad).
type xdpUmemReg struct {
	Addr      uint64
	Len       uint64
	ChunkSize uint32
	Headroom  uint32
	Flags     uint32
	Pad       uint32
}

// sockaddrXDP mirrors struct sockaddr_xdp.
type sockaddrXDP struct {
	Family   uint16
	Flags    uint16
	Ifindex  uint32
	QueueID  uint32
	SharedFD uint32
}

// xdpDesc mirrors struct xdp_desc.
type xdpDesc struct {
	Addr    uint64
	Len     uint32
	Options uint32
}

// xdpRing is one mapped packet ring (rx/tx/fill/comp).
type xdpRing struct {
	producer *uint32
	consumer *uint32
	desc     []xdpDesc
	size     uint32
	mask     uint32 // size-1 (power-of-two rings)
}

// XSKStats exposes socket health for the Node posture report.
type XSKStats struct {
	RX          uint64 // frames received
	RXDropped   uint64 // frames dropped for lack of UMEM buffers
	TX          uint64 // frames transmitted
	TXDropped   uint64
	ParseErrors uint64
}

// XSK is a bound AF_XDP socket sharing one UMEM.
type XSK struct {
	fd       int
	umem     []byte
	umemFD   int
	ifindex  int
	queueID  uint32
	frameSz  uint32
	numFrms  uint32
	headroom uint32

	rx, tx, fill, comp xdpRing

	rxCount  atomic.Uint64
	rxDrop   atomic.Uint64
	txCount  atomic.Uint64
	txDrop   atomic.Uint64
	parseErr atomic.Uint64

	mu      sync.Mutex
	handler func(XSKFrame)
}

// XSKFrame is one parsed L7 frame handed to the inspector.
type XSKFrame struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	TCPFlags         uint8
	Payload          []byte // points into the UMEM (zero copy)
}

// SetHandler installs the frame consumer (called from the RX loop).
func (s *XSK) SetHandler(h func(XSKFrame)) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

// Stats returns a consistent counter snapshot.
func (s *XSK) Stats() XSKStats {
	return XSKStats{
		RX:        s.rxCount.Load(),
		RXDropped: s.rxDrop.Load(),
		TX:        s.txCount.Load(),
		TXDropped: s.txDrop.Load(),
	}
}

// OpenXSK creates and binds an AF_XDP socket for the given NIC queue.
// zeroCopy requests XDP_ZEROCOPY (falls back to XDP_COPY when the driver
// lacks zero-copy support — posture reports which mode engaged).
func OpenXSK(iface string, queueID uint32, frames, frameSize uint32, zeroCopy bool) (*XSK, error) {
	if frames == 0 {
		frames = DefaultUmemFrames
	}
	if frameSize == 0 {
		frameSize = DefaultFrameSize
	}
	if frames&(frames-1) != 0 {
		return nil, fmt.Errorf("af_xdp: frame count %d must be a power of two", frames)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("af_xdp: interface %s: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("af_xdp: socket: %w", err)
	}

	s := &XSK{
		fd:       fd,
		ifindex:  ifi.Index,
		queueID:  queueID,
		frameSz:  frameSize,
		numFrms:  frames,
		headroom: DefaultHeadroom,
	}

	// ① UMEM: allocate frames and register with the kernel.
	umemLen := uint64(frames) * uint64(frameSize)
	umem, err := unix.Mmap(-1, 0, int(umemLen),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("af_xdp: mmap umem: %w", err)
	}
	s.umem = umem

	umemReg := xdpUmemReg{
		Addr:      uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:       umemLen,
		ChunkSize: frameSize,
		Headroom:  s.headroom,
	}
	if err := setsockoptBytes(fd, unix.SOL_XDP, xdpOptUmemReg, umemReg); err != nil {
		s.Close()
		return nil, fmt.Errorf("af_xdp: XDP_UMEM_REG: %w", err)
	}

	// ② Fill/Completion rings (UMEM ownership queues).
	if err := s.createRing(xdpOptFillRing, int(DefaultFillRings)); err != nil {
		s.Close()
		return nil, fmt.Errorf("af_xdp: fill ring: %w", err)
	}
	if err := s.createRing(xdpOptCompRing, int(DefaultCompRings)); err != nil {
		s.Close()
		return nil, fmt.Errorf("af_xdp: comp ring: %w", err)
	}

	// ③ RX/TX rings.
	if err := s.createRing(xdpOptTxRing, int(frames)); err != nil {
		s.Close()
		return nil, fmt.Errorf("af_xdp: tx ring: %w", err)
	}
	// RX ring is created explicitly on kernels that expose XDP_RX_RING;
	// 5.4+ allocates it together with the fill ring. Ignore ENOTSUP.
	_ = s.createRing(xdpOptRxRing, int(frames))

	if err := s.mapRings(); err != nil {
		s.Close()
		return nil, err
	}

	// ④ Bind to the NIC queue.
	bindFlags := uint16(xdpCopy)
	if zeroCopy {
		bindFlags = xdpZerocopy
	}
	sa := sockaddrXDP{
		Family:  unix.AF_XDP,
		Flags:   bindFlags,
		Ifindex: uint32(ifi.Index),
		QueueID: queueID,
	}
	if err := bindXDP(fd, sa); err != nil {
		if zeroCopy {
			// Driver without zero-copy support — retry in copy mode.
			sa.Flags = xdpCopy
			if err2 := bindXDP(fd, sa); err2 != nil {
				s.Close()
				return nil, fmt.Errorf("af_xdp: bind (zerocopy then copy): %w / %v", err, err2)
			}
			log.Printf("af_xdp: %s q%d bound in COPY mode (driver lacks zero-copy)", iface, queueID)
		} else {
			s.Close()
			return nil, fmt.Errorf("af_xdp: bind: %w", err)
		}
	} else if zeroCopy {
		log.Printf("af_xdp: %s q%d bound in ZEROCOPY mode", iface, queueID)
	}

	// ⑤ Seed the fill ring so the NIC can start delivering frames.
	s.refillAll()

	// Register the socket FD into the kernel XSKMAP so the XDP program can
	// steer packets here (queue index = map key).
	if err := s.registerIntoXSKMap(queueID); err != nil {
		log.Printf("af_xdp: XSKMAP registration unavailable: %v (steering disabled)", err)
	}

	return s, nil
}

// registerIntoXSKMap inserts this socket's FD into the program's XSKMAP.
func (s *XSK) registerIntoXSKMap(queue uint32) error {
	mgr := globalXSKManager
	if mgr == nil || mgr.m == nil || mgr.m.Objs == nil || mgr.m.Objs.XsightXsk == nil {
		return fmt.Errorf("xskmap not loaded")
	}
	return mgr.m.Objs.XsightXsk.Update(queue, uint32(s.fd), unix.BPF_ANY)
}

func setsockoptBytes(fd, level, opt int, v interface{}) error {
	b := packNative(v)
	return unix.SetsockoptString(fd, level, opt, string(b))
}

// packNative serializes a struct in native memory layout.
func packNative(v interface{}) []byte {
	sz := unsafe.Sizeof(v)
	buf := make([]byte, sz)
	copy(buf, (*((*[1 << 20]byte)(unsafe.Pointer(&v))))[:sz])
	return buf
}

func bindXDP(fd int, sa sockaddrXDP) error {
	_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return errno
	}
	return nil
}

// createRing asks the kernel to allocate a ring of n descriptors.
func (s *XSK) createRing(opt, n int) error {
	val := uint32(n)
	return unix.SetsockoptInt(s.fd, unix.SOL_XDP, opt, int(val))
}

// mapRings mmaps the four ring control blocks + descriptor arrays.
func (s *XSK) mapRings() error {
	var off xdpMmapOffsets
	offBuf, err := unix.GetsockoptString(s.fd, unix.SOL_XDP, xdpOptMmapOffsets)
	if err != nil {
		return fmt.Errorf("af_xdp: getsockopt XDP_MMAP_OFFSETS: %w", err)
	}
	if len(offBuf) < int(unsafe.Sizeof(off)) {
		return fmt.Errorf("af_xdp: XDP_MMAP_OFFSETS short read")
	}
	copy((*(*[1 << 10]byte)(unsafe.Pointer(&off)))[:], offBuf)

	mapRing := func(ro xdpRingOffset, n uint32) (xdpRing, error) {
		sz := uintptr(ro.Desc) + uintptr(n)*xskRingDescSize
		b, err := unix.Mmap(s.fd, int64(ro.Desc)*int64(os.Getpagesize()), int(sz),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			return xdpRing{}, fmt.Errorf("mmap ring: %w", err)
		}
		r := xdpRing{
			producer: (*uint32)(unsafe.Pointer(&b[ro.Producer])),
			consumer: (*uint32)(unsafe.Pointer(&b[ro.Consumer])),
			size:     n,
			mask:     n - 1,
		}
		r.desc = unsafe.Slice((*xdpDesc)(unsafe.Pointer(&b[ro.Desc])), n)
		return r, nil
	}

	if s.rx, err = mapRing(off.RX, s.numFrms); err != nil {
		return err
	}
	if s.tx, err = mapRing(off.TX, s.numFrms); err != nil {
		return err
	}
	if s.fill, err = mapRing(off.Fill, DefaultFillRings); err != nil {
		return err
	}
	if s.comp, err = mapRing(off.Comp, DefaultCompRings); err != nil {
		return err
	}
	return nil
}

// refillAll returns every UMEM frame to the fill ring.
func (s *XSK) refillAll() {
	nb := s.freeFrames()
	idx := *s.fill.producer
	for i := uint32(0); i < nb; i++ {
		d := &s.fill.desc[(idx+i)&s.fill.mask]
		d.Addr = uint64(i) * uint64(s.frameSz)
		d.Len = 0
	}
	*s.fill.producer = idx + nb
}

func (s *XSK) freeFrames() uint32 {
	return s.fill.size - (*s.fill.producer - *s.fill.consumer)
}

// Run drains the RX ring until stop is closed. Frames are parsed and handed
// to the handler; consumed UMEM frames are returned to the fill ring.
func (s *XSK) Run(stop <-chan struct{}) {
	pollFds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := unix.Poll(pollFds, 100)
		if err != nil && err != unix.EINTR {
			log.Printf("af_xdp: poll: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		s.drainRX()
		s.reapComp()
	}
}

// drainRX reads all available descriptors and dispatches parsed frames.
func (s *XSK) drainRX() {
	for {
		cons := *s.rx.consumer
		prod := *s.rx.producer
		if cons == prod {
			break
		}
		d := &s.rx.desc[cons&s.rx.mask]
		frameAddr := d.Addr
		frameLen := d.Len
		*s.rx.consumer = cons + 1
		s.rxCount.Add(1)

		if frameAddr+uint64(frameLen) > uint64(len(s.umem)) {
			s.parseErr.Add(1)
			s.returnFrame(frameAddr)
			continue
		}
		raw := s.umem[frameAddr : frameAddr+uint64(frameLen)]

		if f, ok := parseXSKFrame(raw); ok {
			s.mu.Lock()
			h := s.handler
			s.mu.Unlock()
			if h != nil {
				h(f)
			}
		} else {
			s.parseErr.Add(1)
		}
		s.returnFrame(frameAddr)
	}
}

// returnFrame hands a UMEM chunk back to the fill ring.
func (s *XSK) returnFrame(addr uint64) {
	if s.freeFrames() == 0 {
		// Fill ring full — kernel will hold; drop accounting happens at RX.
		s.rxDrop.Add(1)
		return
	}
	idx := *s.fill.producer
	d := &s.fill.desc[idx&s.fill.mask]
	d.Addr = addr
	d.Len = 0
	*s.fill.producer = idx + 1
}

// reapComp collects transmitted UMEM frames from the completion ring.
func (s *XSK) reapComp() {
	for {
		cons := *s.comp.consumer
		prod := *s.comp.producer
		if cons == prod {
			break
		}
		*s.comp.consumer = cons + 1
	}
}

// SendRawFrame transmits a fully-formed Ethernet frame from the UMEM.
// Used by the challenge responder to emit HTTP 307 responses.
func (s *XSK) SendRawFrame(umemOffset uint64, length uint32) bool {
	if s.freeTx() == 0 {
		s.txDrop.Add(1)
		return false
	}
	idx := *s.tx.producer
	d := &s.tx.desc[idx&s.tx.mask]
	d.Addr = umemOffset
	d.Len = length
	*s.tx.producer = idx + 1
	s.txCount.Add(1)
	return true
}

func (s *XSK) freeTx() uint32 {
	return s.tx.size - (*s.tx.producer - *s.tx.consumer)
}

// Umem exposes the shared memory region for frame building.
func (s *XSK) Umem() []byte { return s.umem }

// FrameSize returns the UMEM chunk size.
func (s *XSK) FrameSize() uint32 { return s.frameSz }

// Close releases the socket and all mappings.
func (s *XSK) Close() {
	if s.fd >= 0 {
		unix.Close(s.fd)
		s.fd = -1
	}
	if s.umem != nil {
		_ = unix.Munmap(s.umem)
		s.umem = nil
	}
}

// parseXSKFrame extracts L2/L3/L4 + TCP payload from a raw frame.
// Returns ok=false for non-TCP-IPv4 frames (UDP is passed for DNS metrics
// later; L7 inspection is TCP-only today).
func parseXSKFrame(raw []byte) (XSKFrame, bool) {
	var f XSKFrame
	if len(raw) < 14+20 {
		return f, false
	}
	ethType := binary.BigEndian.Uint16(raw[12:14])
	l3 := 14
	switch ethType {
	case 0x8100: // VLAN single tag
		if len(raw) < 18 {
			return f, false
		}
		ethType = binary.BigEndian.Uint16(raw[16:18])
		l3 = 18
	case 0x0800:
	default:
		return f, false
	}
	if ethType != 0x0800 {
		return f, false
	}

	iph := raw[l3:]
	if len(iph) < 20 || iph[0]>>4 != 4 {
		return f, false
	}
	ihl := int(iph[0]&0x0F) * 4
	if ihl < 20 || len(iph) < ihl {
		return f, false
	}
	if iph[9] != 6 { // TCP only
		return f, false
	}
	src := net.IPv4(iph[12], iph[13], iph[14], iph[15])
	dst := net.IPv4(iph[16], iph[17], iph[18], iph[19])

	tcp := iph[ihl:]
	if len(tcp) < 20 {
		return f, false
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || len(tcp) < doff {
		return f, false
	}
	f.SrcIP = src
	f.DstIP = dst
	f.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	f.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	f.TCPFlags = tcp[13]
	payload := tcp[doff:]
	if len(payload) > 0 {
		f.Payload = payload
	}
	return f, true
}

// ---------------------------------------------------------------------------
// Global XSK registry — lets main() own the lifecycle while the bpf package
// wires the socket into the loaded XSKMAP.
// ---------------------------------------------------------------------------

var (
	globalXSKMu      sync.Mutex
	globalXSKManager *XSKManager
)

// XSKManager owns the AF_XDP sockets of this node (one per NIC queue).
type XSKManager struct {
	m       *Manager
	iface   string
	sockets map[uint32]*XSK
	stop    chan struct{}
	wg      sync.WaitGroup
}

// StartXSK opens an AF_XDP socket on iface/queue, registers it in the XSKMAP
// and starts the RX loop feeding `handler`. zeroCopy requests UMEM zero-copy
// binding.
func StartXSK(m *Manager, iface string, queue uint32, frames, frameSize uint32,
	zeroCopy bool, handler func(XSKFrame)) (*XSKManager, error) {
	globalXSKMu.Lock()
	defer globalXSKMu.Unlock()

	s, err := OpenXSK(iface, queue, frames, frameSize, zeroCopy)
	if err != nil {
		return nil, err
	}
	s.SetHandler(handler)

	mgr := &XSKManager{
		m:       m,
		iface:   iface,
		sockets: map[uint32]*XSK{queue: s},
		stop:    make(chan struct{}),
	}
	globalXSKManager = mgr

	mgr.wg.Add(1)
	go func() {
		defer mgr.wg.Done()
		s.Run(mgr.stop)
	}()
	log.Printf("af_xdp: socket started iface=%s queue=%d frames=%d frame_size=%d",
		iface, queue, frames, frameSize)
	return mgr, nil
}

// Close stops all RX loops and releases sockets.
func (x *XSKManager) Close() {
	if x == nil {
		return
	}
	close(x.stop)
	x.wg.Wait()
	for _, s := range x.sockets {
		s.Close()
	}
}

// Sockets returns the managed sockets (for posture reporting).
func (x *XSKManager) Sockets() map[uint32]*XSK {
	if x == nil {
		return nil
	}
	return x.sockets
}
