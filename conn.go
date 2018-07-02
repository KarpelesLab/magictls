package magictls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

type WConn struct {
	conn    net.Conn
	rbuf    []byte
	rbuflen int
	l, r    net.Addr
}

func (c *WConn) Read(b []byte) (int, error) {
	if c.rbuflen > 0 {
		if len(b) == c.rbuflen {
			n := copy(b, c.rbuf)
			c.rbuflen = 0
			return n, nil
		}
		if len(b) > c.rbuflen {
			copy(b, c.rbuf)
			n, err := c.conn.Read(b[c.rbuflen:])
			n += c.rbuflen
			c.rbuflen = 0
			return n, err
		}
		// last case, rbuflen < b
		n := copy(b, c.rbuf)
		c.rbuflen -= n
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	return c.conn.Read(b)
}

func (c *WConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *WConn) Close() error {
	return c.conn.Close()
}

func (c *WConn) LocalAddr() net.Addr {
	return c.l
}

func (c *WConn) RemoteAddr() net.Addr {
	return c.r
}

func (c *WConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *WConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *WConn) parseProxyLine(buf []byte) error {
	s := bytes.Split(buf, []byte{' '})
	if bytes.Compare(s[0], []byte("PROXY")) != 0 {
		return errors.New("http: invalid proxy line provided")
	}

	// see: http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
	switch string(s[1]) {
	case "UNKNOWN":
		return nil // do nothing
	case "TCP4", "TCP6":
		if len(s) < 6 {
			return errors.New("http: not enough parameters for TCP PROXY")
		}
		rPort, _ := strconv.Atoi(string(s[4]))
		lPort, _ := strconv.Atoi(string(s[5]))
		c.r = &net.TCPAddr{IP: net.ParseIP(string(s[2])), Port: rPort}
		c.l = &net.TCPAddr{IP: net.ParseIP(string(s[3])), Port: lPort}
		return nil
	default:
		return errors.New("http: invalid proxy transport provided")
	}
}

func (c *WConn) parseProxyV2Data(verCmd, fam uint8, d []byte) error {
	if verCmd>>4&0xf != 0x2 {
		return errors.New("http: unsupported PROXYv2 header version")
	}
	switch verCmd & 0xf {
	case 0x0: // LOCAL (health check, etc)
		return nil
	case 0x1: // PROXY
		break
	default:
		return errors.New("http: unsupported proxy type data")
	}

	switch fam >> 4 & 0xf {
	case 0x0: // UNSPEC
		return nil
	case 0x1, 0x2: // AF_INET, AF_INET6
		break
	case 0x3: // AF_UNIX
		return nil
	default:
		return errors.New("http: unsupported proxy address family")
	}

	switch fam & 0xf {
	case 0x0: // UNSPEC
		return nil
	case 0x1, 0x2: // STREAM, DGRAM
		break
	default:
		return errors.New("http: unsupported proxy protocol")
	}

	// sanitarization done, let's parse data
	b := bytes.NewBuffer(d)
	var rPort, lPort uint16

	switch fam >> 4 & 0xf {
	case 0x1: // AF_INET
		if len(d) < 12 {
			return errors.New("http: not enough data in proxy v2 header for ipv4")
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
			return errors.New("http: not enough data in proxy v2 header for ipv6")
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
