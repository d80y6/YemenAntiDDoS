package l7

// Scalar counter keys on the L7 event wire. The Node collector emits them and
// the Controller l7store parses them; both sides must reference these
// constants so a rename cannot silently zero a Console field.
const (
	KeyHTTPRequests     = "http_requests"
	KeyHTTPRPS          = "http_rps"
	KeyHandshakes       = "tls_handshakes"
	KeyHSPS             = "tls_hsps"
	KeyMissingSNI       = "tls_sni_missing"
	KeySlowlorisConns   = "slowloris_conns"
	KeySlowlorisSources = "slowloris_sources"
	KeyUniqueSources    = "unique_sources"
	KeyWindowSeconds    = "window_seconds"
	KeyAlertThreshold   = "alert_threshold"
)
