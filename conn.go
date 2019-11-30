package magictls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

// Conn is used to prepend data to the data stream when we need to
// unread what we've read. It can be used as a net.Conn.
type Conn struct {
	conn net.Conn
	rbuf []byte
	l, r net.Addr
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

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) parseProxyLine(buf []byte) error {
	s := bytes.Split(buf, []byte{' '})
	if bytes.Compare(s[0], []byte("PROXY")) != 0 {
		return errors.New("magictls: invalid proxy line provided")
	}

	// see: magictls://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
	switch string(s[1]) {
	case "UNKNOWN":
		return nil // do nothing
	case "TCP4", "TCP6":
		if len(s) < 6 {
			return errors.New("magictls: not enough parameters for TCP PROXY")
		}
		rPort, _ := strconv.Atoi(string(s[4]))
		lPort, _ := strconv.Atoi(string(s[5]))
		c.r = &net.TCPAddr{IP: net.ParseIP(string(s[2])), Port: rPort}
		c.l = &net.TCPAddr{IP: net.ParseIP(string(s[3])), Port: lPort}
		return nil
	default:
		return errors.New("magictls: invalid proxy transport provided")
	}
}

func (c *Conn) parseProxyV2Data(verCmd, fam uint8, d []byte) error {
	if verCmd>>4&0xf != 0x2 {
		return errors.New("magictls: unsupported PROXYv2 header version")
	}
	switch verCmd & 0xf {
	case 0x0: // LOCAL (health check, etc)
		return nil
	case 0x1: // PROXY
		break
	default:
		return errors.New("magictls: unsupported proxy type data")
	}

	switch fam >> 4 & 0xf {
	case 0x0: // UNSPEC
		return nil
	case 0x1, 0x2: // AF_INET, AF_INET6
		break
	case 0x3: // AF_UNIX
		return nil
	default:
		return errors.New("magictls: unsupported proxy address family")
	}

	switch fam & 0xf {
	case 0x0: // UNSPEC
		return nil
	case 0x1, 0x2: // STREAM, DGRAM
		break
	default:
		return errors.New("magictls: unsupported proxy protocol")
	}

	// sanitarization done, let's parse data
	b := bytes.NewBuffer(d)
	var rPort, lPort uint16

	switch fam >> 4 & 0xf {
	case 0x1: // AF_INET
		if len(d) < 12 {
			return errors.New("magictls: not enough data in proxy v2 header for ipv4")
		}
		rip := make([]byte, 4)
		lip := make([]byte, 4)
		binary.Read(b, binary.BigEndian, rip)
		binary.Read(b, binary.BigEndian, lip)
		binary.Read(b, binary.BigEndian, &lPort)
		binary.Read(b, binary.BigEndian, &rPort)

		c.r = &net.TCPAddr{IP: rip, Port: int(rPort)}
		c.l = &net.TCPAddr{IP: lip, Port: int(lPort)}
	case 0x2: // AF_INET6
		if len(d) < 36 {
			return errors.New("magictls: not enough data in proxy v2 header for ipv6")
		}
		rip := make([]byte, 16)
		lip := make([]byte, 16)
		binary.Read(b, binary.BigEndian, rip)
		binary.Read(b, binary.BigEndian, lip)
		binary.Read(b, binary.BigEndian, &lPort)
		binary.Read(b, binary.BigEndian, &rPort)

		c.r = &net.TCPAddr{IP: rip, Port: int(rPort)}
		c.l = &net.TCPAddr{IP: lip, Port: int(lPort)}
	}
	return nil
}
