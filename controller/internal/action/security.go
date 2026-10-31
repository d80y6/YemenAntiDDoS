package action

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"unicode"
)

func vtyshToken(s string) error {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("unsafe vtysh token")
	}
	return nil
}

func vtyshTokens(prefix, routeMap string) error {
	for field, value := range map[string]string{"prefix": prefix, "route-map": routeMap} {
		if vtyshToken(value) != nil {
			return fmt.Errorf("unsafe vtysh token: %s", field)
		}
	}
	return nil
}

// WebhookTransport is shared by action delivery and the connector test endpoint.
var WebhookTransport http.RoundTripper = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableKeepAlives = true
	return t
}()

var errWebhookRequest = errors.New("request build failed")

func safeWebhookError(statusCode int, err error) string {
	if statusCode != 0 {
		return fmt.Sprintf("HTTP %d", statusCode)
	}
	var timeout net.Error
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var urlErr *url.Error
	switch {
	case errors.Is(err, errWebhookRequest), errors.As(err, &urlErr) && urlErr.Op == "parse":
		return "request build failed"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.As(err, &dns):
		return "dns lookup failed"
	case errors.As(err, &cert), errors.As(err, &record):
		return "tls error"
	default:
		return "transport error"
	}
}

// SafeWebhookError exposes the same fixed vocabulary to the API package.
func SafeWebhookError(statusCode int, err error) string { return safeWebhookError(statusCode, err) }
