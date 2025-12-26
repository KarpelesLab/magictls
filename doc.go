// Package magictls provides automatic protocol detection for TCP connections.
//
// It enables a single TCP port to transparently handle multiple protocols:
//   - Automatic TLS detection: distinguishes between TLS/SSL and plaintext
//   - PROXY protocol support: detects PROXY v1 and v2 headers for real client IPs
//   - Protocol routing: routes connections based on TLS-negotiated protocols (ALPN)
//   - Extensible filters: custom protocol detection via the Filter interface
//
// # Basic Usage
//
// Use Listen to create a listener that automatically detects TLS:
//
//	socket, err := magictls.Listen("tcp", ":8080", tlsConfig)
//	if err != nil {
//		log.Fatal(err)
//	}
//	log.Fatal(http.Serve(socket, handler))
//
// # Protocol Requirements
//
// This library works with protocols where the client sends the first data and
// sends at least 16 bytes initially. This works well with HTTP, TLS/SSL, etc.
// Protocols where the server speaks first (POP3, IMAP, SMTP) may not work
// unless TLS is required (use ForceTLS filter).
//
// # PROXY Protocol
//
// When behind load balancers (AWS ELB, Google Cloud LB), the PROXY protocol
// preserves the real client IP. Only connections from allowed proxy IPs
// (see SetAllowedProxies) will have their PROXY headers parsed.
//
// # Custom Filters
//
// Implement the Filter type to add custom protocol detection:
//
//	func MyFilter(conn *magictls.Conn, srv *magictls.Listener) error {
//		buf, err := conn.PeekUntil(4)
//		if err != nil {
//			return err
//		}
//		// Inspect buf and decide what to do
//		return nil
//	}
//	socket.Filters = []magictls.Filter{magictls.DetectProxy, MyFilter}
package magictls
