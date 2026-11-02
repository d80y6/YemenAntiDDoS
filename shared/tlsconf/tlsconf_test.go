package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"

	"os"
	"path/filepath"
	"testing"
	"time"
)

type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	dir    string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		dir:    t.TempDir(),
	}
}

// issue writes <name>.crt/<name>.key into the PKI dir and returns their paths.
func (p *testPKI) issue(t *testing.T, name, nodeID string, dnsNames ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
	}
	if nodeID != "" {
		tmpl.URIs = append(tmpl.URIs, NodeURI(nodeID))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(p.dir, name+".crt")
	keyPath := filepath.Join(p.dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func (p *testPKI) caFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(p.dir, "ca.crt")
	if err := os.WriteFile(path, p.caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMutualTLSInterop boots a real TLS listener using ServerConfig, dials it
// with ClientConfig, and asserts the server can recover the node identity from
// the client certificate's URI SAN.
func TestMutualTLSInterop(t *testing.T) {
	p := newTestPKI(t)
	caFile := p.caFile(t)
	serverCert, serverKey := p.issue(t, "controller", "", "controller")
	nodeCert, nodeKey := p.issue(t, "node-01", "node-01")

	srvCfg, err := ServerConfig(FileConfig{CAFile: caFile, CertFile: serverCert, KeyFile: serverKey})
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	cliCfg, err := ClientConfig(FileConfig{
		CAFile:     caFile,
		CertFile:   nodeCert,
		KeyFile:    nodeKey,
		ServerName: "controller",
	})
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		id  string
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer conn.Close()
		tconn := conn.(*tls.Conn)
		if err := tconn.Handshake(); err != nil {
			resCh <- result{err: err}
			return
		}
		state := tconn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			resCh <- result{err: errNoPeerCert}
			return
		}
		id, err := NodeIDFromCert(state.PeerCertificates[0])
		resCh <- result{id: id, err: err}
	}()

	dconn, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer dconn.Close()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("server side: %v", res.err)
	}
	if res.id != "node-01" {
		t.Fatalf("identity = %q, want node-01", res.id)
	}
	if v := dconn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Fatalf("negotiated version = %x, want TLS 1.3", v)
	}
}

// TestServerRejectsUnknownCA proves RequireAndVerifyClientCert is effective:
// a client certificate signed by a different CA must fail the handshake.
func TestServerRejectsUnknownCA(t *testing.T) {
	p := newTestPKI(t)
	caFile := p.caFile(t)
	serverCert, serverKey := p.issue(t, "controller", "", "controller")

	other := newTestPKI(t)
	rogueCert, rogueKey := other.issue(t, "rogue", "node-99")

	srvCfg, err := ServerConfig(FileConfig{CAFile: caFile, CertFile: serverCert, KeyFile: serverKey})
	if err != nil {
		t.Fatal(err)
	}
	cliCfg, err := ClientConfig(FileConfig{
		CAFile:     caFile,
		CertFile:   rogueCert,
		KeyFile:    rogueKey,
		ServerName: "controller",
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serverErr <- conn.(*tls.Conn).Handshake()
	}()

	// In TLS 1.3 the client finishes its half of the handshake before the
	// server's alert arrives, so the authoritative signal is the server-side
	// handshake result, not the client dial error.
	conn, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
	if err == nil {
		defer conn.Close()
		_, _ = conn.Write([]byte("x"))
		_, _ = conn.Read(make([]byte, 1))
	}
	if err := <-serverErr; err == nil {
		t.Fatal("server accepted a client certificate from an untrusted CA")
	}
}

var errNoPeerCert = errors.New("no peer certificate presented")
