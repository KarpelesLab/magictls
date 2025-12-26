package magictls

import (
	"bufio"
	"crypto/tls"
	"net"
	"time"
)

// Conn wraps a net.Conn to provide peek/unread functionality for protocol
// detection. Data can be read (peeked) without consuming it, allowing filters
// to inspect the initial bytes of a connection before deciding how to handle it.
//
// Conn implements the net.Conn interface and can be used anywhere a net.Conn
// is expected. The local and remote addresses can be overridden, which is useful
// for PROXY protocol support where the real client address is different from
// the connection's apparent address.
type Conn struct {
	conn net.Conn // underlying connection
	rbuf []byte   // peek buffer (data read but not yet consumed)
	l, r net.Addr // local and remote addresses (may be overridden)
	used bool     // true if addresses were modified
}

func (c *Conn) isUsed() bool {
	if len(c.rbuf) != 0 {
		return true
	}
	return c.used
}

// Read reads data into b. If there is data in the peek buffer, it is returned
// first. Otherwise, Read reads from the underlying connection.
func (c *Conn) Read(b []byte) (int, error) {
	if ln := len(c.rbuf); ln > 0 {
		if len(b) >= ln {
			n := copy(b, c.rbuf)
			c.rbuf = nil
			return n, nil
		}
		// rbuf did not fit, return as much as we can and keep the rest
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	return c.conn.Read(b)
}

// PeekMore will perform a single read from the socket, and return the data
// read so far. May return an error if the socket was closed (in which case
// data may still be returned if it was read before).
func (c *Conn) PeekMore(count int) ([]byte, error) {
	buf := make([]byte, count)
	n, err := c.conn.Read(buf)
	if err != nil {
		return c.rbuf, err
	}

	buf = buf[:n] // cut buf
	c.rbuf = append(c.rbuf, buf...)
	return c.rbuf, nil
}

// PeekUntil will block until at least count bytes were read, or an error
// happens.
func (c *Conn) PeekUntil(count int) ([]byte, error) {
	for len(c.rbuf) < count {
		_, err := c.PeekMore(count - len(c.rbuf))
		if err != nil {
			return c.rbuf, err
		}
	}

	return c.rbuf, nil
}

// SkipPeek will skip count bytes from the peek buffer, or strip the whole
// buffer if count is larger or equal to the buffer.
func (c *Conn) SkipPeek(count int) {
	// skip X bytes from previous peeks
	if len(c.rbuf) <= count {
		c.rbuf = nil
	} else {
		c.rbuf = c.rbuf[count:]
	}
}

// Write writes data to the underlying connection.
func (c *Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address, which may have been overridden
// by SetLocalAddr (e.g., from PROXY protocol data).
func (c *Conn) LocalAddr() net.Addr {
	return c.l
}

// RemoteAddr returns the remote network address, which may have been overridden
// by SetRemoteAddr (e.g., from PROXY protocol data).
func (c *Conn) RemoteAddr() net.Addr {
	return c.r
}

// SetLocalAddr overrides the local address returned by LocalAddr.
// This is typically used by the PROXY protocol filter to set the real
// destination address from the PROXY header.
func (c *Conn) SetLocalAddr(l net.Addr) {
	c.l = l
	c.used = true
}

// SetRemoteAddr overrides the remote address returned by RemoteAddr.
// This is typically used by the PROXY protocol filter to set the real
// client address from the PROXY header.
func (c *Conn) SetRemoteAddr(r net.Addr) {
	c.r = r
	c.used = true
}

// SetDeadline sets the read and write deadlines on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Unwrap returns the underlying net.Conn if the peek buffer is empty,
// or nil if there is still buffered data that hasn't been consumed.
// This can be used to access the original connection after protocol detection.
func (c *Conn) Unwrap() net.Conn {
	if c.rbuf != nil {
		// can't unwrap yet at this point
		return nil
	}
	return c.conn
}

// NetConn returns the underlying tcp connection. Read or write to this connection will
// likely corrupt it.
func (c *Conn) NetConn() net.Conn {
	res := c.conn

	for {
		if c2, ok := res.(interface{ NetConn() net.Conn }); ok {
			res = c2.NetConn()
		} else {
			// no more levels
			return res
		}
	}
}

// GetTlsConn will attempt to unwrap the given connection in order to locate
// a TLS connection, or return nil if none found.
func GetTlsConn(c net.Conn) *tls.Conn {
	for {
		switch cv := c.(type) {
		case *tls.Conn:
			return cv
		case interface{ Unwrap() net.Conn }:
			c = cv.Unwrap()
		default:
			return nil
		}
	}
}

// HijackedConn allows returning a simple net.Conn from a Conn+ReadWriter as returned by http.Hijacker.Hijack()
func HijackedConn(c net.Conn, io *bufio.ReadWriter, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	ln := io.Reader.Buffered()
	if ln == 0 {
		// nothing in reader, let's just return c
		return c, nil
	}
	data, err := io.Reader.Peek(ln) // should not fail
	if err != nil {
		return nil, err
	}
	return &Conn{conn: c, rbuf: data, l: c.LocalAddr(), r: c.RemoteAddr()}, nil
}
