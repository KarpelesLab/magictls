package magictls

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

type queuePoint struct {
	c net.Conn
	e error
}

// MagicListener is a TCP network listener supporting TLS and
// PROXY protocol automatically. It assumes no matter what the used protocol
// is, at least 16 bytes will always be initially sent (true for HTTP).
type MagicListener struct {
	port      *net.TCPListener
	addr      *net.TCPAddr
	queue     chan queuePoint
	tlsConfig *tls.Config
	http      *http.Server
}

func Listen(network string, listen string) *MagicListener {
	r := new(MagicListener)
	var err error

	r.addr, err = net.ResolveTCPAddr(network, listen)
	if err != nil {
		panic(err)
	}

	r.port, err = net.ListenTCP(network, r.addr)
	if err != nil {
		panic(err)
	}
	r.queue = make(chan queuePoint)
	r.tlsConfig = new(tls.Config)
	r.tlsConfig.GetCertificate = retrieveTlsCertificate
	r.tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	r.http = new(http.Server)
	r.http.TLSConfig = r.tlsConfig

	go r.listenLoop()
	return r
}

func (r *MagicListener) Accept() (net.Conn, error) {
	// TODO implement timeouts?
	p := <-r.queue
	return p.c, p.e
}

func (r *MagicListener) Close() error {
	return r.port.Close()
}

func (r *MagicListener) Addr() net.Addr {
	return r.addr
}

func (r *MagicListener) shutdown() {
	r.port.Close()
}

func (r *MagicListener) ServeHttp() error {
	return r.http.Serve(r)
}

func (r *MagicListener) listenLoop() {
	for {
		c, err := r.port.AcceptTCP()
		if err != nil {
			r.queue <- queuePoint{e: err}
			return
		} else {
			go r.handleNewConnection(c)
		}
	}
}

func (r *MagicListener) handleNewConnection(c *net.TCPConn) {
	buf := make([]byte, 16)
	n, err := io.ReadFull(c, buf)
	if err != nil {
		if err != io.EOF {
			r.queue <- queuePoint{e: fmt.Errorf("magictls: failed reading from connection: %s", err)}
		}
		c.Close()
		return
	}
	if n != 16 {
		r.queue <- queuePoint{e: fmt.Errorf("magictls: failed reading at least 16 bytes from connection: %s", err)}
		c.Close()
		return
	}
	cw := new(magicTlsBuffer)
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
				r.queue <- queuePoint{e: errors.New("magictls: failed to read proxy v2 data")}
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
				r.queue <- queuePoint{e: errors.New("magictls: failed to read full line of proxy protocol")}
				c.Close()
				return
			}
			buf = append(buf, pr[:n]...)

			pos = bytes.IndexByte(buf, '\n')
			if pos > 0 {
				break
			}
			if len(buf) > 128 {
				r.queue <- queuePoint{e: errors.New("magictls: got proxy protocol intro but line is too long, closing connection")}
				c.Close()
				return
			}
		}

		err = cw.parseProxyLine(buf[:pos])
		if err != nil {
			log.Printf("magictls: failed to parse PROXY line (%s): %s\n", buf[:pos], err)
		}

		buf = buf[pos+1:]

		if len(buf) < 16 {
			xbuf := make([]byte, 16-len(buf))
			n, err = io.ReadFull(c, xbuf)
			if err != nil {
				log.Printf("magictls: failed to read frame after proxy info: %s", err)
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
		r.queue <- queuePoint{c: cs}
		return
	}
	if buf[0] == 0x16 {
		// SSLv3, TLS
		cs := tls.Server(cw, r.tlsConfig)
		r.queue <- queuePoint{c: cs}
		return
	}

	// send to serve
	r.queue <- queuePoint{c: cw}
}

func (p *MagicListener) String() string {
	return p.addr.String()
}
