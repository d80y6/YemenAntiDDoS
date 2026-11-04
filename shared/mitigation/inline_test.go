package mitigation

import (
	"net"
	"testing"
	"time"
)

func TestInlineRuleValidate(t *testing.T) {
	validRule := InlineRule{
		ID:           "rule-1",
		TargetPrefix: "192.0.2.1/32",
		Protocol:     6,
		DstPort:      443,
		Action:       ActionDrop,
	}
	if err := validRule.Validate(); err != nil {
		t.Fatalf("expected valid rule, got error: %v", err)
	}

	invalidTarget := InlineRule{
		ID:           "rule-2",
		TargetPrefix: "invalid-ip",
		Action:       ActionPass,
	}
	if err := invalidTarget.Validate(); err == nil {
		t.Fatal("expected error for invalid target IP, got nil")
	}

	invalidRateLimit := InlineRule{
		ID:           "rule-3",
		TargetPrefix: "198.51.100.0/24",
		Action:       ActionRateLimit,
		RateLimitPPS: 0,
	}
	if err := invalidRateLimit.Validate(); err == nil {
		t.Fatal("expected error for zero rate limit pps, got nil")
	}
}

func TestSYNCookieGenerationAndVerification(t *testing.T) {
	secret := []byte("carrier-grade-secret-seed-32bytes")
	srcIP := net.ParseIP("198.51.100.55")
	dstIP := net.ParseIP("203.0.113.10")
	srcPort := uint16(54321)
	dstPort := uint16(443)
	clientISN := uint32(123456789)

	now := time.Now()
	cookie := GenerateSYNCookie(srcIP, dstIP, srcPort, dstPort, clientISN, now, secret)

	// In TCP, the client's ACK sequence number is server_ISN + 1
	ackSeq := cookie + 1
	if !VerifySYNCookie(srcIP, dstIP, srcPort, dstPort, clientISN, ackSeq, now, secret) {
		t.Fatalf("cookie verification failed for legitimate ACK")
	}

	// Verify failure on altered IP
	badSrcIP := net.ParseIP("198.51.100.56")
	if VerifySYNCookie(badSrcIP, dstIP, srcPort, dstPort, clientISN, ackSeq, now, secret) {
		t.Fatalf("cookie verification should have failed for altered source IP")
	}

	// Verify failure on altered Port
	if VerifySYNCookie(srcIP, dstIP, srcPort+1, dstPort, clientISN, ackSeq, now, secret) {
		t.Fatalf("cookie verification should have failed for altered source port")
	}

	// Verify failure on altered ISN
	if VerifySYNCookie(srcIP, dstIP, srcPort, dstPort, clientISN+1, ackSeq, now, secret) {
		t.Fatalf("cookie verification should have failed for altered client ISN")
	}
}
