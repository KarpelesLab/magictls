package magictls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strconv"
)

var allowedProxyIps []*net.IPNet

func init() {
	SetAllowedProxies([]string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fd00::/8"})
}

// SetAllowedProxies allows modifying the list of IP addresses allowed to use
// proxy protocol. Any host matching a CIDR listed in here will be trusted to
// provide the client's real IP.
//
// By default all local IPs are allowed as these cannot appear on Internet.
//
// SetAllowedProxies([]string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fd00::/8"})
func SetAllowedProxies(cidrs []string) error {
	allowed := []*net.IPNet{}

	for _, s := range cidrs {
		_, ipn, err := net.ParseCIDR(s)
		if err != nil {
			return err
		}
		allowed = append(allowed, ipn)
	}

	allowedProxyIps = allowed
	return nil
}

func DetectProxy(cw *Conn, srv *MagicListener) error {
	proxyAllow := false

	switch ipaddr := cw.r.(type) {
	case *net.TCPAddr:
		for _, n := range allowedProxyIps {
			if n.Contains(ipaddr.IP) {
				proxyAllow = true
				break
			}
		}
	case *net.IPAddr:
		for _, n := range allowedProxyIps {
			if n.Contains(ipaddr.IP) {
				proxyAllow = true
				break
			}
		}
	}

	if !proxyAllow {
		return nil
	}

	buf, err := cw.PeekUntil(16)
	if err != nil {
		return err
	}

	// detect proxy
	if bytes.Compare(buf[:12], []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}) == 0 {
		// proxy protocol v2
		b := bytes.NewBuffer(buf[12:])
		var verCmd, fam uint8
		var ln uint16
		binary.Read(b, binary.BigEndian, &verCmd)
		binary.Read(b, binary.BigEndian, &fam)
		binary.Read(b, binary.BigEndian, &ln)
		var d []byte
		if ln > 0 {
			tmp, err := cw.PeekUntil(16 + int(ln))
			if err != nil {
				log.Printf("magictls: failed to read proxy v2 data")
				return err
			}
			d = tmp[16:]
		}
		return parseProxyV2Data(cw, verCmd, fam, d)
	} else if bytes.Compare(buf[:6], []byte("PROXY ")) == 0 {
		// proxy protocol v1
		var pos int

		for {
			buf, err = cw.PeekMore(128) // max proxy line length is 107 bytes in theory
			if err != nil {
				log.Printf("magictls: failed to read full line of proxy protocol")
				return err
			}

			pos = bytes.IndexByte(buf, '\n')
			if pos > 0 {
				break
			}
			if len(buf) > 128 {
				log.Printf("magictls: got proxy protocol intro but line is too long, ignoring")
				return nil
			}
		}

		err := parseProxyLine(cw, buf[:pos])
		if err != nil {
			log.Printf("magictls: failed to parse PROXY line (%s): %s\n", buf[:pos], err)
			return err
		}

		cw.SkipPeek(pos + 1)
	}
	return nil
}

func parseProxyLine(c *Conn, buf []byte) error {
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

func parseProxyV2Data(c *Conn, verCmd, fam uint8, d []byte) error {
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
