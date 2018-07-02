package magictls

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
)

type ChanListener struct {
	parent *Port
	queue  chan net.Conn
}

func (c *ChanListener) Accept() (net.Conn, error) {
	return <-c.queue, nil
}

func (c *ChanListener) Close() error {
	return nil
}

func (c *ChanListener) Addr() net.Addr {
	return c.parent.addr
}

type Port struct {
	port      *net.TCPListener
	addr      *net.TCPAddr
	queue     chan net.Conn
	tlsConfig *tls.Config
	http      *http.Server
}

func Listen(network string, listen string) *Port {
	r := new(Port)
	var err error

	r.addr, err = net.ResolveTCPAddr(network, listen)
	if err != nil {
		panic(err)
	}

	r.port, err = net.ListenTCP(network, r.addr)
	if err != nil {
		panic(err)
	}
	r.queue = make(chan net.Conn)
	r.tlsConfig = new(tls.Config)
	r.tlsConfig.GetCertificate = retrieveTlsCertificate
	r.tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	r.http = new(http.Server)
	r.http.TLSConfig = r.tlsConfig

	go r.listenLoop()
	go r.serverLoop()
	return r
}

func (r *Port) shutdown() {
	r.port.Close()
}

func (r *Port) serverLoop() {
	l := new(ChanListener)
	l.parent = r
	l.queue = r.queue
	err := r.http.Serve(l)
	if err != nil {
		log.Printf("http: Failed to listen to socket %s: %s", r, err)
	}
}

func (r *Port) listenLoop() {
	for {
		c, err := r.port.AcceptTCP()
		if err != nil {
			log.Printf("http: failed to accept connection: %s", err)
			return
		} else {
			go r.handleNewConnection(c)
		}
	}
}

func (r *Port) handleNewConnection(c *net.TCPConn) {
	buf := make([]byte, 16)
	n, err := io.ReadFull(c, buf)
	if err != nil {
		if err != io.EOF {
			log.Printf("Failed reading from connection: %s", err)
		}
		c.Close()
		return
	}
	if n != 16 {
		log.Printf("Failed reading at least 16 bytes from connection: %s", err)
		c.Close()
		return
	}
	cw := new(WConn)
	cw.conn = c
	cw.rbuf = buf
	cw.rbuflen = len(buf)
	cw.l = c.LocalAddr()
	cw.r = c.RemoteAddr()

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
				log.Printf("http: failed to read proxy v2 data")
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
				log.Printf("http: failed to read full line of proxy protocol")
				c.Close()
				return
			}
			buf = append(buf, pr[:n]...)

			pos = bytes.IndexByte(buf, '\n')
			if pos > 0 {
				break
			}
			if len(buf) > 128 {
				log.Printf("http: got proxy protocol intro but line is too long, closing connection")
				c.Close()
				return
			}
		}

		err = cw.parseProxyLine(buf[:pos])
		if err != nil {
			log.Printf("http: failed to parse PROXY line (%s): %s\n", buf[:pos], err)
		}

		buf = buf[pos+1:]

		if len(buf) < 16 {
			xbuf := make([]byte, 16-len(buf))
			n, err = io.ReadFull(c, xbuf)
			if err != nil {
				log.Printf("http: failed to read frame after proxy info: %s", err)
				c.Close()
				return
			}
			buf = append(buf, xbuf[:n]...)
		}
		cw.rbuf = buf
		cw.rbuflen = len(buf)
	}

	if buf[0]&0x80 == 0x80 {
		// SSLv2, probably. At least, not HTTP
		cs := tls.Server(cw, r.tlsConfig)
		r.queue <- cs
		return
	}
	if buf[0] == 0x16 {
		// SSLv3, TLS
		cs := tls.Server(cw, r.tlsConfig)
		r.queue <- cs
		return
	}

	// send to serve
	r.queue <- cw
}

func (p *Port) String() string {
	return p.addr.String()
}
