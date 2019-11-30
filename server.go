package magictls

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

type queuePoint struct {
	c  net.Conn
	rc *net.TCPConn
	e  error
}

// MagicListener is a TCP network listener supporting TLS and
// PROXY protocol automatically. It assumes no matter what the used protocol
// is, at least 16 bytes will always be initially sent (true for HTTP).
type MagicListener struct {
	port      *net.TCPListener
	addr      *net.TCPAddr
	queue     chan queuePoint
	TLSConfig *tls.Config
	Mode      TLSMode
}

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
// SetAllowedProxies([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"})
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

// Listen creates a hybrid TCP/TLS listener accepting connections on the given
// network address using net.Listen. The configuration config must be non-nil
// and must include at least one certificate or else set GetCertificate. If
// not, then only PROXY protocol support will be available.
//
// If the connection uses TLS protocol, then Accept() returned net.Conn will
// actually be a tls.Conn object.
func Listen(network, laddr string, config *tls.Config) (*MagicListener, error) {
	r := new(MagicListener)
	var err error

	r.addr, err = net.ResolveTCPAddr(network, laddr)
	if err != nil {
		return nil, err
	}

	r.port, err = net.ListenTCP(network, r.addr)
	if err != nil {
		return nil, err
	}
	r.queue = make(chan queuePoint)
	r.TLSConfig = config

	// listenloop will accept connections then push them to the queue
	go r.listenLoop()
	return r, nil
}

// ListenNull creates a listener that is not actually listening to anything,
// but can be used to push connections via PushConn. This can be useful to use
// a http.Server with custom listeners.
func ListenNull() *MagicListener {
	return &MagicListener{queue: make(chan queuePoint)}
}

// PushConn allows pushing an existing connection to the queue as if it had
// just been accepted by the server. No auto-detection will be performed.
func (r *MagicListener) PushConn(c net.Conn) {
	r.queue <- queuePoint{c: c}
}

func (r *MagicListener) Accept() (net.Conn, error) {
	// TODO implement timeouts?
	p := <-r.queue
	return p.c, p.e
}

func (r *MagicListener) AcceptRaw() (net.Conn, *net.TCPConn, error) {
	// TODO implement timeouts?
	p := <-r.queue
	return p.c, p.rc, p.e
}

func (r *MagicListener) Close() error {
	if r.port != nil {
		if err := r.port.Close(); err != nil {
			return err
		}
		r.port = nil
	}
	return nil
}

func (r *MagicListener) Addr() net.Addr {
	return r.addr
}

func (r *MagicListener) shutdown() {
	r.Close()
}

func (r *MagicListener) listenLoop() {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		c, err := r.port.AcceptTCP()
		if err != nil {
			// check for temporary error
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			r.queue <- queuePoint{e: err}
			return
		} else {
			go r.HandleConn(c)
		}
	}
}

// HandleConn will run detection on a given incoming connection and attempt to
// find if it should parse any kind of PROXY headers, or TLS handshake/etc.
func (r *MagicListener) HandleConn(c *net.TCPConn) {
	buf := make([]byte, 16)
	n, err := io.ReadFull(c, buf)
	if (err != nil) && (err != io.EOF) {
		log.Printf("magictls: failed reading from connection: %s", err)
		c.Close()
		return
	}
	cw := new(magicTlsBuffer)
	cw.conn = c
	cw.rbuf = buf
	cw.rbuflen = n
	cw.l = c.LocalAddr()
	cw.r = c.RemoteAddr()
	if n < 16 {
		// less than 16 bytes of data means we reached EOF, implying this isn't SSL or PROXY header, pass along
		r.queue <- queuePoint{c: cw, rc: c}
		return
	}

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

	if proxyAllow {
		if bytes.Compare(buf[:12], []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}) == 0 {
			// proxy protocol v2
			b := bytes.NewBuffer(buf[12:])
			var verCmd, fam uint8
			var ln uint16
			binary.Read(b, binary.BigEndian, &verCmd)
			binary.Read(b, binary.BigEndian, &fam)
			binary.Read(b, binary.BigEndian, &ln)
			d := make([]byte, ln)
			if ln > 0 {
				_, err := io.ReadFull(c, d)
				if err != nil {
					log.Printf("magictls: failed to read proxy v2 data")
					c.Close()
					return
				}
			}
			cw.parseProxyV2Data(verCmd, fam, d)
		} else if bytes.Compare(buf[:6], []byte("PROXY ")) == 0 {
			// proxy protocol v1
			pr := make([]byte, 128) // max proxy line length is 107 bytes in theory
			var pos int

			for {
				n, err = c.Read(pr)
				if err != nil {
					log.Printf("magictls: failed to read full line of proxy protocol")
					c.Close()
					return
				}
				buf = append(buf, pr[:n]...)

				pos = bytes.IndexByte(buf, '\n')
				if pos > 0 {
					break
				}
				if len(buf) > 128 {
					log.Printf("magictls: got proxy protocol intro but line is too long, closing connection")
					c.Close()
					return
				}
			}

			err = cw.parseProxyLine(buf[:pos])
			if err != nil {
				log.Printf("magictls: failed to parse PROXY line (%s): %s\n", buf[:pos], err)
				c.Close()
				return
			}

			buf = buf[pos+1:]

			if len(buf) < 16 {
				xbuf := make([]byte, 16-len(buf))
				n, err = io.ReadFull(c, xbuf)
				if (err != nil) && (err != io.EOF) {
					log.Printf("magictls: failed to read frame after proxy info: %s", err)
					c.Close()
					return
				}
				if n > 0 {
					buf = append(buf, xbuf[:n]...)
				}
			}
			cw.rbuf = buf
			cw.rbuflen = len(buf)
		}
	}

	if r.TLSConfig == nil {
		// send to queue without checking for tls
		r.queue <- queuePoint{c: cw, rc: c}
		return
	}

	if len(buf) == 0 {
		// likely got a EOF earlier and no data was read past the PROXY header
		r.queue <- queuePoint{c: cw, rc: c}
		return
	}

	switch r.Mode {
	case Always:
		// don't think
		cs := tls.Server(cw, r.TLSConfig)
		r.queue <- queuePoint{c: cs, rc: c}
		return
	case Never:
		r.queue <- queuePoint{c: cw, rc: c}
		return
	}

	// perform auto-detection
	if buf[0]&0x80 == 0x80 {
		// SSLv2, probably. At least, not HTTP
		cs := tls.Server(cw, r.TLSConfig)
		r.queue <- queuePoint{c: cs, rc: c}
		return
	}
	if buf[0] == 0x16 {
		// SSLv3, TLS
		cs := tls.Server(cw, r.TLSConfig)
		r.queue <- queuePoint{c: cs, rc: c}
		return
	}

	// send to serve
	r.queue <- queuePoint{c: cw, rc: c}
}

func (p *MagicListener) String() string {
	return p.addr.String()
}
