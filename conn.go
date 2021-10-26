package magictls

import (
	"crypto/tls"
	"net"
	"time"
)

// Conn is used to prepend data to the data stream when we need to
// unread what we've read. It can be used as a net.Conn.
type Conn struct {
	conn net.Conn
	rbuf []byte
	l, r net.Addr
	used bool
}

func (c *Conn) isUsed() bool {
	if len(c.rbuf) != 0 {
		return true
	}
	return c.used
}

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

func (c *Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.l
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.r
}

func (c *Conn) SetLocalAddr(l net.Addr) {
	c.l = l
	c.used = true
}

func (c *Conn) SetRemoteAddr(r net.Addr) {
	c.r = r
	c.used = true
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Unwrap() net.Conn {
	if c.rbuf != nil {
		// can't unwrap yet at this point
		return nil
	}
	return c.conn
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
