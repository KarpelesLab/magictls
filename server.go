package magictls

import (
	"crypto/tls"
	"io"
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

	Filters []Filter
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
	r.Filters = []Filter{DetectProxy, DetectTLS}

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

// Accept blocks until a connection is available, then return said connection
// or an error if the listener was closed.
func (r *MagicListener) Accept() (net.Conn, error) {
	// TODO implement timeouts?
	p := <-r.queue
	return p.c, p.e
}

// AcceptRaw blocks until a connection is available, then return said connection
// alongside the original TCP socket, or an error if the listener was closed.
func (r *MagicListener) AcceptRaw() (net.Conn, *net.TCPConn, error) {
	// TODO implement timeouts?
	p := <-r.queue
	return p.c, p.rc, p.e
}

// Close() closes the socket.
func (r *MagicListener) Close() error {
	if r.port != nil {
		if err := r.port.Close(); err != nil {
			return err
		}
		r.port = nil
	}
	return nil
}

// Addr returns the address the socket is currently listening on, or nil for
// null listeners.
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

			// send error (TODO if more than one thread is calling Accept, only one will return)
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
	cw := &Conn{
		conn: c,
		l:    c.LocalAddr(),
		r:    c.RemoteAddr(),
	}

	// for each filter
	for _, f := range r.Filters {
		err := f(cw, r)
		if err != nil {
			if err == io.EOF {
				// ignore EOF errors, those are typically not important
				continue
			}
			if ov, ok := err.(*Override); ok {
				// perform override
				cw = &Conn{
					conn: ov.Conn,
					l:    ov.Conn.LocalAddr(),
					r:    ov.Conn.RemoteAddr(),
				}
				continue
			}

			// For now we ignore all filter errors
		}
	}

	// send to serve
	r.queue <- queuePoint{c: cw, rc: c}
}

func (p *MagicListener) String() string {
	return p.addr.String()
}
