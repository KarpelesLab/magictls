package magictls

import "net"

// Override is a special error type returned by filters to signal that the
// connection should be replaced with a different one (e.g., after TLS handshake)
// or that a specific protocol has been negotiated.
//
// When a filter returns an *Override as an error, the magictls listener will:
//   - Replace the current connection with Override.Conn if non-nil
//   - Record the negotiated protocol from Override.Protocol if non-empty
//   - Continue processing remaining filters with the new connection
type Override struct {
	// Conn is the replacement connection (e.g., *tls.Conn after TLS handshake).
	// If nil, the current connection is kept.
	Conn net.Conn

	// Protocol is the negotiated protocol name (e.g., from TLS ALPN).
	// Used for routing connections to protocol-specific listeners.
	Protocol string
}

// Error implements the error interface. Override is returned as an error
// by filters to trigger connection replacement.
func (o *Override) Error() string {
	return "Connection override required"
}
