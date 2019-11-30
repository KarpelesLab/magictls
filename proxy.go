package magictls

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
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
		cw.parseProxyV2Data(verCmd, fam, d)
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

		err = cw.parseProxyLine(buf[:pos])
		if err != nil {
			log.Printf("magictls: failed to parse PROXY line (%s): %s\n", buf[:pos], err)
			return err
		}

		cw.SkipPeek(pos + 1)
	}
	return nil
}
