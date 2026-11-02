// Package tlsconf centralises mutual-TLS configuration shared by the xSight
// Controller (gRPC server) and the xSight Node (gRPC client).
//
// Design (Pillar 1 — Transport Security Hardening):
//
//   - Transport: TLS 1.3 minimum. TLS 1.2 is deliberately NOT allowed: the
//     controller<->node link carries per-IP traffic telemetry and control
//     pushes, and TLS 1.3 removes the renegotiation / compression classes of
//     downgrade attack entirely.
//   - Authentication: mutual X.509. The Controller requires a client
//     certificate (RequireAndVerifyClientCert) and the Node requires a server
//     certificate. Both chains must terminate at the deployment CA.
//   - Identity: the node identity is NOT taken from the NodeHandshake
//     protobuf message — it is taken from the certificate URI SAN
//     "spiffe://xsight/node/<node_id>". This closes the Sybil hole where any
//     peer that won one handshake could later claim another node_id in
//     StatsReport / ControlStream.
//   - Rotation: the leaf certificate is reloaded from disk on a short intervalCap
//     via GetCertificate / GetClientCertificate hooks, so an operator can
//     renew a leaf without restarting the data plane.
//
// Everything here is deliberately dependency-free (stdlib crypto/tls only)
// so it can live in the shared module and be used by both binaries.
package tlsconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// NodeURIPrefix is the stable identity namespace embedded in every node leaf
// certificate: spiffe://xsight/node/<node_id>.
const NodeURIPrefix = "spiffe://xsight/node/"

// NodeURI returns the URI SAN that identifies nodeID.
func NodeURI(nodeID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: "xsight", Path: "/node/" + nodeID}
}

// NodeIDFromCert extracts the xSight node identity from a verified peer
// certificate's URI SAN. It returns an error when the certificate carries no
// node identity, which the Controller treats as unauthenticated.
func NodeIDFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("tlsconf: nil certificate")
	}
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" && u.Host == "xsight" && strings.HasPrefix(u.Path, "/node/") {
			id := strings.TrimPrefix(u.Path, "/node/")
			if id == "" {
				return "", errors.New("tlsconf: empty node id in URI SAN")
			}
			return id, nil
		}
	}
	return "", errors.New("tlsconf: certificate has no spiffe://xsight/node/<id> URI SAN")
}

// FileConfig describes on-disk material. CAFile, CertFile and KeyFile are
// mandatory. ServerName is only meaningful for the client (Node) side.
type FileConfig struct {
	// CAFile is the PEM bundle of CAs trusted for the peer chain.
	CAFile string
	// CertFile is the PEM leaf certificate (the issuing chain may be inlined).
	CertFile string
	// KeyFile is the PEM private key for CertFile.
	KeyFile string

	// ServerName is the name the Node expects in the Controller certificate.
	// Empty means "use the gRPC target host".
	ServerName string

	// AllowLegacyTLS12 permits TLS 1.2 when the deployment cannot upgrade yet.
	// Defaults to false and is surfaced as a loud log line by callers.
	AllowLegacyTLS12 bool
}

func (c FileConfig) validate(side string) error {
	var missing []string
	if strings.TrimSpace(c.CAFile) == "" {
		missing = append(missing, "ca_file")
	}
	if strings.TrimSpace(c.CertFile) == "" {
		missing = append(missing, "cert_file")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		missing = append(missing, "key_file")
	}
	if len(missing) > 0 {
		return fmt.Errorf("tlsconf: %s TLS requires %s", side, strings.Join(missing, ", "))
	}
	return nil
}

// minVersion returns the allowed floor version.
func (c FileConfig) minVersion() uint16 {
	if c.AllowLegacyTLS12 {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

// loadPool reads a PEM bundle into a fresh pool. Unlike the zero-value
// SetOptions trick, this fails loudly on unreadable or empty files.
func loadPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: read CA %s: %w", path, err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tlsconf: CA %s contains no PEM certificate", path)
	}
	return p, nil
}

// reloader caches a certificate pair and refreshes it when the files change on
// disk. It is safe for concurrent use; Only one load happens at a time.
type reloader struct {
	mu       sync.RWMutex
	certFile string
	keyFile  string
	loaded   *tls.Certificate
	loadedAt time.Time
	stat     os.FileInfo // mtime+size of key file at load time
}

// reloadInterval bounds how often a handshake pays the stat cost. Without it,
// a reconnect storm would stat two files per TLS handshake.
const reloadInterval = 30 * time.Second

func newReloader(certFile, keyFile string) (*reloader, error) {
	r := &reloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.certificate(); err != nil {
		return nil, err
	}
	return r, nil
}

// certificate returns the cached pair, reloading it when the key file's
// mtime or size changed and the throttle interval elapsed.
func (r *reloader) certificate() (*tls.Certificate, error) {
	fi, err := os.Stat(r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: stat key: %w", err)
	}

	r.mu.RLock()
	cached := r.loaded
	same := r.stat != nil &&
		r.stat.ModTime().Equal(fi.ModTime()) &&
		r.stat.Size() == fi.Size() &&
		time.Since(r.loadedAt) < reloadInterval
	r.mu.RUnlock()
	if cached != nil && same {
		return cached, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.loaded != nil {
			// Keep last-known-good material: a partially written rotation
			// must not drop every in-flight handshake.
			return r.loaded, nil
		}
		return nil, fmt.Errorf("tlsconf: load keypair: %w", err)
	}
	r.loaded, r.stat, r.loadedAt = &pair, fi, time.Now()
	return &pair, nil
}

// ServerConfig builds the Controller-side *tls.Config for mutual TLS.
//
// The Controller presents its own leaf certificate and REQUIRES a client
// certificate whose chain terminates in CAFile.X509. Certificate identity is
// not checked here — it is verified per-RPC by the gRPC auth interceptor,
// which compares the certificate's node URI SAN against the node_id carried
// in each message. Splitting the two jobs keeps tlsconf free of application
// knowledge (which nodes exist, which are enabled, which are revoked).
func ServerConfig(fc FileConfig) (*tls.Config, error) {
	if err := fc.validate("server"); err != nil {
		return nil, err
	}
	clientPool, err := loadPool(fc.CAFile)
	if err != nil {
		return nil, err
	}
	reload, err := newReloader(fc.CertFile, fc.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             fc.minVersion(),
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return reload.certificate() },
		ClientCAs:              clientPool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		SessionTicketsDisabled: true,
	}, nil
}

// ClientConfig builds the Node-side *tls.Config for mutual TLS.
//
// The Node presents its identity certificate and verifies the Controller
// against CAFile.X509, with ServerName as the expected peer name. When
// ServerName is empty, gRPC's authority (the dial target host) is used, which
// is the correct default but breaks when dialling a bare IP whose
// certificate carries only a DNS SAN — set ServerName explicitly then.
func ClientConfig(fc FileConfig) (*tls.Config, error) {
	if err := fc.validate("client"); err != nil {
		return nil, err
	}
	rootPool, err := loadPool(fc.CAFile)
	if err != nil {
		return nil, err
	}
	reload, err := newReloader(fc.CertFile, fc.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             fc.minVersion(),
		RootCAs:                rootPool,
		ServerName:             fc.ServerName,
		GetClientCertificate:   func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return reload.certificate() },
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
	}, nil
}

// LeafNotAfter reports the expiry of the currently loaded leaf certificate, so
// callers can warn about an imminent rotation instead of discovering it from a
// failed handshake at the worst possible moment.
func (fc FileConfig) LeafNotAfter() (time.Time, error) {
	crt, err := fc.LeafCertificate()
	if err != nil {
		return time.Time{}, err
	}
	return crt.NotAfter, nil
}

// LeafCertificate parses the leaf certificate stored in CertFile. It is used
// by the console to display expiry, identity and fingerprint without ever
// exposing private key material.
func (fc FileConfig) LeafCertificate() (*x509.Certificate, error) {
	data, err := os.ReadFile(fc.CertFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("tlsconf: cert file has no PEM block")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

// CertInfo is a safe, JSON-serialisable view of a certificate. It never
// contains key material, which makes it suitable for the management API.
type CertInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serial_number"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DNSNames     []string `json:"dns_names,omitempty"`
	URIs         []string `json:"uris,omitempty"`
	Fingerprint  string   `json:"fingerprint_sha256"`
	IsCA         bool     `json:"is_ca"`
}

// DescribeCert renders the public fields of cert for display.
func DescribeCert(cert *x509.Certificate) CertInfo {
	if cert == nil {
		return CertInfo{}
	}
	uris := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	return CertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:     append([]string(nil), cert.DNSNames...),
		URIs:         uris,
		Fingerprint:  Fingerprint(cert),
		IsCA:         cert.IsCA,
	}
}

// Fingerprint returns the SHA-256 fingerprint of the DER encoding in the
// colon-separated hexadecimal form used by OpenSSL.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Describe loads and describes the leaf certificate in fc.CertFile.
func (fc FileConfig) Describe() (CertInfo, error) {
	crt, err := fc.LeafCertificate()
	if err != nil {
		return CertInfo{}, err
	}
	return DescribeCert(crt), nil
}
