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
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
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
	xskUmemDescSize   = 8  // sizeof(__u64) in fill/completion rings
)

// Ring mmap offsets from if_xdp.h. The kernel does not report these in
// XDP_MMAP_OFFSETS (only the byte offsets within each ring), so the rings must
// be mapped at these fixed page-aligned PGOFF magic values.
const (
	xdpPgoffRXRing   uint64 = 0
	xdpPgoffTXRing   uint64 = 0x80000000
	xdpPgoffFillRing uint64 = 0x100000000
	xdpPgoffCompRing uint64 = 0x180000000
)

// ringPlan describes one mmap of an AF_XDP ring.
type ringPlan struct {
	name     string
	pgoff    uint64
	nmemb    uint32
	descSize uint32
}

// ringMapPlans returns the mmap geometry for a UMEM of n frames: rx/tx hold
// xdp_desc entries, fill/completion hold 8-byte UMEM offsets.
func ringMapPlans(n, rx uint32) [4]ringPlan {
	if rx == 0 {
		rx = n
	}
	return [4]ringPlan{
		{"rx", xdpPgoffRXRing, rx, xskRingDescSize},
		{"tx", xdpPgoffTXRing, n, xskRingDescSize},
		{"fill", xdpPgoffFillRing, DefaultFillRings, xskUmemDescSize},
		{"comp", xdpPgoffCompRing, DefaultCompRings, xskUmemDescSize},
	}
}

// ringMapSize is the byte length to mmap: the descriptor offset reported by the
// kernel plus nmemb descriptors of the given stride.
func ringMapSize(ro xdpRingOffset, nmemb, descSize uint32) uintptr {
	return uintptr(ro.Desc) + uintptr(nmemb)*uintptr(descSize)
}

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

// xdpRing is one mapped packet ring (rx/tx/fill/comp). RX/TX rings expose
// xdp_desc descriptors; fill/completion rings expose 8-byte UMEM offsets.
type xdpRing struct {
	producer *uint32
	consumer *uint32
	desc     []xdpDesc
	addrs    []uint64
	size     uint32
	mask     uint32 // size-1 (power-of-two rings)
}

// Ring indices are shared with the kernel. Plain loads/stores let the compiler
// or CPU reorder descriptor accesses past index publication on weakly ordered
// targets (arm64); Go atomics provide the release/acquire ordering the kernel
// expects (it uses smp_load_acquire/smp_store_release on the same fields).
func (r *xdpRing) loadProducer() uint32   { return atomic.LoadUint32(r.producer) }
func (r *xdpRing) loadConsumer() uint32   { return atomic.LoadUint32(r.consumer) }
func (r *xdpRing) storeProducer(v uint32) { atomic.StoreUint32(r.producer, v) }
func (r *xdpRing) storeConsumer(v uint32) { atomic.StoreUint32(r.consumer, v) }

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
	rxRingSize         uint32
	rxMap, txMap       []byte
	fillMap, compMap   []byte
	pending            []uint64            // UMEM frames awaiting fill-ring space
	pendingTX          map[uint64]struct{} // RX slots handed to the TX ring

	rxCount  atomic.Uint64
	rxDrop   atomic.Uint64
	txCount  atomic.Uint64
	txDrop   atomic.Uint64
	parseErr atomic.Uint64

	mu      sync.Mutex
	handler func(XSKFrame)

	closeOnce sync.Once
}

// XSKFrame is one parsed L7 frame handed to the inspector.
type XSKFrame struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	TCPFlags         uint8
	Payload          []byte // points into the UMEM (zero copy)
	Seq, Ack         uint32 // TCP sequence numbers (host order)
	FrameOffset      uint64 // frame start in UMEM (TX replies reuse the slot)
	EthHdr           []byte // 14-18 L2 bytes incl. ethertype/VLAN (into UMEM)
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
		RX:          s.rxCount.Load(),
		RXDropped:   s.rxDrop.Load(),
		TX:          s.txCount.Load(),
		TXDropped:   s.txDrop.Load(),
		ParseErrors: s.parseErr.Load(),
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
		fd:        fd,
		ifindex:   ifi.Index,
		queueID:   queueID,
		frameSz:   frameSize,
		numFrms:   frames,
		headroom:  DefaultHeadroom,
		pendingTX: make(map[uint64]struct{}),
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
	// RX ring is created explicitly where the kernel exposes XDP_RX_RING.
	// Older kernels default the RX ring to the fill-ring size, so fall back to
	// that geometry instead of mapping a ring larger than the kernel created.
	s.rxRingSize = frames
	if err := s.createRing(xdpOptRxRing, int(frames)); err != nil {
		if !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EOPNOTSUPP) {
			s.Close()
			return nil, fmt.Errorf("af_xdp: rx ring: %w", err)
		}
		s.rxRingSize = DefaultFillRings
	}

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
// Callers must hold globalXSKMu (StartXSK does), which guards globalXSKManager.
func (s *XSK) registerIntoXSKMap(queue uint32) error {
	mgr := globalXSKManager
	if mgr == nil || mgr.m == nil || mgr.m.Objs == nil || mgr.m.Objs.XsightXsk == nil {
		return fmt.Errorf("xskmap not loaded")
	}
	return mgr.m.Objs.XsightXsk.Update(queue, uint32(s.fd), unix.BPF_ANY)
}

func setsockoptBytes(fd, level, opt int, v interface{}) error {
	return unix.SetsockoptString(fd, level, opt, string(structBytes(v)))
}

// structBytes serializes a value in native memory layout. The size and byte
// image come from the concrete type, not the interface header: unsafe.Sizeof
// on an interface would return a pointer pair and copy garbage to the kernel.
func structBytes(v interface{}) []byte {
	rv := reflect.ValueOf(v)
	sz := int(rv.Type().Size())
	buf := make([]byte, sz)
	reflect.NewAt(rv.Type(), unsafe.Pointer(&buf[0])).Elem().Set(rv)
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

	plans := ringMapPlans(s.numFrms, s.rxRingSize)
	if s.rx, s.rxMap, err = mapRing(s.fd, off.RX, plans[0]); err != nil {
		return err
	}
	if s.tx, s.txMap, err = mapRing(s.fd, off.TX, plans[1]); err != nil {
		return err
	}
	if s.fill, s.fillMap, err = mapRing(s.fd, off.Fill, plans[2]); err != nil {
		return err
	}
	if s.comp, s.compMap, err = mapRing(s.fd, off.Comp, plans[3]); err != nil {
		return err
	}
	return nil
}

// mapRing maps one ring at its fixed PGOFF magic offset. ro carries the byte
// offsets of the producer/consumer/descriptor area within that mapping.
func mapRing(fd int, ro xdpRingOffset, p ringPlan) (xdpRing, []byte, error) {
	sz := ringMapSize(ro, p.nmemb, p.descSize)
	b, err := unix.Mmap(fd, int64(p.pgoff), int(sz),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return xdpRing{}, nil, fmt.Errorf("af_xdp: mmap %s ring: %w", p.name, err)
	}
	r := xdpRing{
		producer: (*uint32)(unsafe.Pointer(&b[ro.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&b[ro.Consumer])),
		size:     p.nmemb,
		mask:     p.nmemb - 1,
	}
	if p.descSize == xskRingDescSize {
		r.desc = unsafe.Slice((*xdpDesc)(unsafe.Pointer(&b[ro.Desc])), p.nmemb)
	} else {
		r.addrs = unsafe.Slice((*uint64)(unsafe.Pointer(&b[ro.Desc])), p.nmemb)
	}
	return r, b, nil
}

// refillAll returns every UMEM frame to the fill ring. It never hands out more
// addresses than the UMEM actually owns, even though the fill ring can be larger
// than numFrms.
func (s *XSK) refillAll() {
	s.flushPending()
	nb := s.freeFrames()
	if nb > s.numFrms {
		nb = s.numFrms
	}
	idx := s.fill.loadProducer()
	for i := uint32(0); i < nb; i++ {
		s.fill.addrs[(idx+i)&s.fill.mask] = uint64(i) * uint64(s.frameSz)
	}
	s.fill.storeProducer(idx + nb)
}

func (s *XSK) freeFrames() uint32 {
	return s.fill.size - (s.fill.loadProducer() - s.fill.loadConsumer())
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
		// Reap TX completions regardless of RX activity: the completion ring
		// is not signalled through POLLIN, so this is the only progress path.
		s.reapComp()
		if n == 0 {
			continue
		}
		s.drainRX()
	}
}

// drainRX reads all available descriptors and dispatches parsed frames.
func (s *XSK) drainRX() {
	for {
		cons := s.rx.loadConsumer()
		prod := s.rx.loadProducer()
		if cons == prod {
			break
		}
		d := &s.rx.desc[cons&s.rx.mask]
		frameAddr := d.Addr
		frameLen := d.Len
		s.rx.storeConsumer(cons + 1)
		s.rxCount.Add(1)

		if frameAddr+uint64(frameLen) > uint64(len(s.umem)) {
			s.parseErr.Add(1)
			s.returnFrame(frameAddr)
			continue
		}
		raw := s.umem[frameAddr : frameAddr+uint64(frameLen)]

		if f, ok := parseXSKFrame(raw, frameAddr); ok {
			s.mu.Lock()
			h := s.handler
			s.mu.Unlock()
			if h != nil {
				h(f)
			}
		} else {
			s.parseErr.Add(1)
		}
		// A reply handed the slot to the TX ring; the completion returns it.
		if _, txOwned := s.pendingTX[frameAddr]; !txOwned {
			s.returnFrame(frameAddr)
		}
	}
}

// returnFrame hands a UMEM chunk back to the fill ring. If the ring is full
// the address is queued in pending and retried later, so frames are never
// lost (a lost address would permanently shrink the UMEM).
func (s *XSK) returnFrame(addr uint64) {
	if s.freeFrames() == 0 {
		s.flushPending()
	}
	if s.freeFrames() == 0 {
		s.pending = append(s.pending, addr)
		return
	}
	idx := s.fill.loadProducer()
	s.fill.addrs[idx&s.fill.mask] = addr
	s.fill.storeProducer(idx + 1)
}

// flushPending drains queued UMEM addresses into the fill ring.
func (s *XSK) flushPending() {
	for len(s.pending) > 0 && s.freeFrames() > 0 {
		idx := s.fill.loadProducer()
		s.fill.addrs[idx&s.fill.mask] = s.pending[0]
		s.fill.storeProducer(idx + 1)
		s.pending = s.pending[1:]
	}
}

// reapComp collects transmitted UMEM frames from the completion ring and
// returns them to the fill ring so the kernel can reuse them for RX.
func (s *XSK) reapComp() {
	for {
		cons := s.comp.loadConsumer()
		prod := s.comp.loadProducer()
		if cons == prod {
			break
		}
		if s.freeFrames() == 0 {
			s.flushPending()
			if s.freeFrames() == 0 {
				// Fill ring full: leave the entry in the completion ring so
				// the frame is not lost; retried on the next loop.
				break
			}
		}
		addr := s.comp.addrs[cons&s.comp.mask]
		s.comp.storeConsumer(cons + 1)
		delete(s.pendingTX, addr) // TX finished with the slot; now reclaimable
		s.returnFrame(addr)
	}
	s.flushPending()
}

// SendRawFrame transmits a fully-formed Ethernet frame from the UMEM.
// Used by the challenge responder to emit HTTP 307 responses.
func (s *XSK) SendRawFrame(umemOffset uint64, length uint32) bool {
	if s.freeTx() == 0 {
		s.txDrop.Add(1)
		return false
	}
	idx := s.tx.loadProducer()
	d := &s.tx.desc[idx&s.tx.mask]
	d.Addr = umemOffset
	d.Len = length
	s.tx.storeProducer(idx + 1)
	s.txCount.Add(1)
	xskKickTX(s)
	return true
}

// SendReplyFrame writes reply into the UMEM frame that carried f (at offset)
// and queues the slot for TX. The RX path must not reclaim it: the TX
// completion does. Must run on the socket's Run goroutine (the RX handler).
func (s *XSK) SendReplyFrame(offset uint64, reply []byte) bool {
	if len(reply) == 0 {
		return false
	}
	// Stay inside the frame that carried f: a reply larger than the UMEM
	// chunk would overwrite the adjacent frame, and a write past the UMEM
	// end hits unmapped memory.
	if offset%uint64(s.frameSz)+uint64(len(reply)) > uint64(s.frameSz) ||
		offset >= uint64(len(s.umem)) {
		return false
	}
	if _, dup := s.pendingTX[offset]; dup {
		return false // already in flight; a second claim would double-return the slot
	}
	copy(s.umem[offset:], reply)
	s.pendingTX[offset] = struct{}{}
	if !s.SendRawFrame(offset, uint32(len(reply))) {
		delete(s.pendingTX, offset)
		return false
	}
	return true
}

// kickTX notifies the kernel that descriptors were added to the TX ring. AF_XDP
// has no separate ioctl for this: a zero-length sendto() on the socket is the
// documented doorbell.
func (s *XSK) kickTX() {
	for {
		err := unix.Sendto(s.fd, nil, unix.MSG_DONTWAIT, nil)
		if err == nil {
			return
		}
		if err == unix.EINTR {
			continue
		}
		if err != unix.EAGAIN && err != unix.EWOULDBLOCK &&
			err != unix.ENOBUFS && err != unix.ENETDOWN {
			log.Printf("af_xdp: TX kick: %v", err)
			s.txDrop.Add(1)
		}
		return
	}
}

func (s *XSK) freeTx() uint32 {
	return s.tx.size - (s.tx.loadProducer() - s.tx.loadConsumer())
}

// Umem exposes the shared memory region for frame building.
func (s *XSK) Umem() []byte { return s.umem }

// FrameSize returns the UMEM chunk size.
func (s *XSK) FrameSize() uint32 { return s.frameSz }

// Close releases the socket and all mappings. Safe to call more than once.
func (s *XSK) Close() {
	s.closeOnce.Do(func() {
		if s.fd >= 0 {
			unix.Close(s.fd)
			s.fd = -1
		}
		for _, m := range []*[]byte{&s.rxMap, &s.txMap, &s.fillMap, &s.compMap} {
			if len(*m) > 0 {
				_ = unix.Munmap(*m)
				*m = nil
			}
		}
		if s.umem != nil {
			_ = unix.Munmap(s.umem)
			s.umem = nil
		}
	})
}

// parseXSKFrame extracts L2/L3/L4 + TCP payload from a raw frame.
// frameOffset is the frame's start in the UMEM so replies can reuse the slot.
// Returns ok=false for non-TCP-IPv4 frames (UDP is passed for DNS metrics
// later; L7 inspection is TCP-only today).
func parseXSKFrame(raw []byte, frameOffset uint64) (XSKFrame, bool) {
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
	f.Seq = binary.BigEndian.Uint32(tcp[4:8])
	f.Ack = binary.BigEndian.Uint32(tcp[8:12])
	f.FrameOffset = frameOffset
	f.EthHdr = raw[:l3]
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
	m         *Manager
	iface     string
	sockets   map[uint32]*XSK
	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// StartXSK opens an AF_XDP socket on iface/queue, registers it in the XSKMAP
// and starts the RX loop feeding `handler`. zeroCopy requests UMEM zero-copy
// binding.
//
// The manager must be installed in the global registry before OpenXSK runs:
// OpenXSK registers the socket FD into the XSKMAP, and registration resolves the
// map through globalXSKManager.
func StartXSK(m *Manager, iface string, queue uint32, frames, frameSize uint32,
	zeroCopy bool, handler func(XSKFrame)) (*XSKManager, error) {
	globalXSKMu.Lock()
	defer globalXSKMu.Unlock()

	mgr := &XSKManager{
		m:       m,
		iface:   iface,
		sockets: make(map[uint32]*XSK),
		stop:    make(chan struct{}),
	}
	prev := globalXSKManager
	globalXSKManager = mgr

	s, err := openXSKFn(iface, queue, frames, frameSize, zeroCopy)
	if err != nil {
		globalXSKManager = prev
		return nil, err
	}
	s.SetHandler(handler)
	mgr.sockets[queue] = s

	mgr.wg.Add(1)
	go func() {
		defer mgr.wg.Done()
		s.Run(mgr.stop)
	}()
	log.Printf("af_xdp: socket started iface=%s queue=%d frames=%d frame_size=%d",
		iface, queue, frames, frameSize)
	return mgr, nil
}

// openXSKFn is a test seam for StartXSK's registration-ordering test.
var openXSKFn = OpenXSK

// xskKickTX is a test seam so the TX doorbell can be observed.
var xskKickTX = func(s *XSK) { s.kickTX() }

// Close stops all RX loops and releases sockets.
func (x *XSKManager) Close() {
	if x == nil {
		return
	}
	x.closeOnce.Do(func() {
		close(x.stop)
		x.wg.Wait()
		for _, s := range x.sockets {
			s.Close()
		}
		globalXSKMu.Lock()
		if globalXSKManager == x {
			globalXSKManager = nil
		}
		globalXSKMu.Unlock()
	})
}

// Sockets returns the managed sockets (for posture reporting).
func (x *XSKManager) Sockets() map[uint32]*XSK {
	if x == nil {
		return nil
	}
	return x.sockets
}
