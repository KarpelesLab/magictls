package magictls

import "time"

// tcpKeepaliveConn defines methods typically available on TCP connections to enable keepalive
type tcpKeepaliveConn interface {
	SetKeepAlive(keepalive bool) error
	SetKeepAlivePeriod(d time.Duration) error
}
