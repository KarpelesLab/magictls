package magictls

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var ErrDuplicateProtocol = errors.New("protocol already has a listener")

type queuePoint struct {
	c net.Conn
	e error
}

// Listener is a TCP network listener supporting TLS and
// PROXY protocol automatically. It assumes no matter what the used protocol
// is, at least 16 bytes will always be initially sent (true for HTTP).
type Listener struct {
	port    *net.TCPListener
	addr    net.Addr
	queue   chan queuePoint
	proto   map[string]*protoListener
	protoLk sync.RWMutex

	TLSConfig *tls.Config
	Filters   []Filter
	*log.Logger

	// threads
	thCnt     uint32
	thMax     uint32
	thCntLock sync.RWMutex
	thCntCond sync.Cond
}

// Listen creates a hybrid TCP/TLS listener accepting connections on the given
// network address using net.Listen. The configuration config must be non-nil
// and must include at least one certificate or else set GetCertificate. If
// not, then only PROXY protocol support will be available.
//
// If the connection uses TLS protocol, then Accept() returned net.Conn will
// actually be a tls.Conn object.
func Listen(network, laddr string, config *tls.Config) (*Listener, error) {
	r := &Listener{
		proto: make(map[string]*protoListener),
	}

	addr, err := net.ResolveTCPAddr(network, laddr)
	if err != nil {
		return nil, err
	}

	r.port, err = net.ListenTCP(network, addr)
	if err != nil {
		return nil, err
	}

	r.addr = r.port.Addr()
	r.queue = make(chan queuePoint, 8)
	r.TLSConfig = config
	r.Filters = []Filter{DetectProxy, DetectTLS}
	r.thMax = 64

	// listenloop will accept connections then push them to the queue
	go r.listenLoop()
	return r, nil
}

// ListenNull creates a listener that is not actually listening to anything,
// but can be used to push connections via PushConn. This can be useful to use
// a http.Server with custom listeners.
func ListenNull() *Listener {
	return &Listener{
		queue:   make(chan queuePoint, 8),
		proto:   make(map[string]*protoListener),
		Filters: []Filter{DetectProxy, DetectTLS},
	}
}

// ProtoListener returns a net.Listener that will receive connections for which
// TLS is enabled and the specified protocol(s) have been negociated between
// client and server.
func (r *Listener) ProtoListener(proto ...string) (net.Listener, error) {
	r.protoLk.Lock()
	defer r.protoLk.Unlock()

	// check if none of proto are taken
	for _, pr := range proto {
		if _, found := r.proto[pr]; found {
			return nil, ErrDuplicateProtocol
		}
	}

	// create listener, register
	l := &protoListener{
		proto:  proto,
		queue:  make(chan *queuePoint, 8),
		parent: r,
	}

	for _, pr := range proto {
		r.proto[pr] = l
	}

	return l, nil
}

// SetThreads sets the number of threads (goroutines) magictls will spawn in
// parallel when handling incoming connections. Note that once a connection
// leaves Accept() it is not tracked anymore.
// Filters will however run in parallel for those connections, meaning that
// one connection's handshake taking time will not block other connections.
func (r *Listener) SetThreads(count uint32) {
	r.thCntLock.Lock()
	defer r.thCntLock.Unlock()

	r.thMax = count
}

// GetRunningThreads returns the current number of running threads.
func (r *Listener) GetRunningThreads() uint32 {
	r.thCntLock.RLock()
	defer r.thCntLock.RUnlock()

	return r.thCnt
}

// Accept blocks until a connection is available, then return said connection
// or an error if the listener was closed.
func (r *Listener) Accept() (net.Conn, error) {
	// TODO implement timeouts?
	p, ok := <-r.queue
	if !ok {
		return nil, io.EOF
	}

	return p.c, p.e
}

// processFilters is run in a thread and will execute filters as needed.
func (r *Listener) processFilters(c net.Conn) {
	defer func() {
		r.thCntLock.Lock()
		r.thCnt -= 1
		r.thCntLock.Unlock()
	}()

	cw := &Conn{
		conn: c,
		l:    c.LocalAddr(),
		r:    c.RemoteAddr(),
	}

	var tlsconn *tls.Conn
	var negociatedProtocol string

	// for each filter
	for _, f := range r.Filters {
		err := f(cw, r)
		if err != nil {
			if err == io.EOF {
				// ignore EOF errors, those are typically not important
				continue
			}
			if ov, ok := err.(*Override); ok {
				if ov.Conn != nil {
					if t, ok := ov.Conn.(*tls.Conn); ok {
						// keep this tls connection nearby
						tlsconn = t
					}
					// perform override
					cw = &Conn{
						conn: ov.Conn,
						l:    ov.Conn.LocalAddr(),
						r:    ov.Conn.RemoteAddr(),
					}
				}
				if ov.Protocol != "" {
					negociatedProtocol = ov.Protocol
				}
				continue
			}

			// For now we ignore all filter errors
			if r.Logger != nil {
				r.Logger.Printf("filter error on new connection: %s", err)
			}
			cw.Close()
			return
		}
	}

	var final net.Conn
	final = cw
	if cw.rbuf == nil {
		// skip cw
		final = cw.conn
	}

	if tlsconn != nil && negociatedProtocol == "" {
		// special case: this is a tls socket. Check NegotiatedProtocol
		negociatedProtocol = tlsconn.ConnectionState().NegotiatedProtocol
	}

	if negociatedProtocol != "" {
		// grab lock
		r.protoLk.RLock()
		v, ok := r.proto[negociatedProtocol]
		r.protoLk.RUnlock()

		if ok {
			// send value
			v.queue <- &queuePoint{c: final, e: nil}
			return
		}
	}
	r.queue <- queuePoint{c: final}
}

// Close() closes the socket.
func (r *Listener) Close() error {
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
func (r *Listener) Addr() net.Addr {
	return r.addr
}

func (r *Listener) listenLoop() {
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

			// send error & close
			r.queue <- queuePoint{e: err}
			close(r.queue)
			return
		} else {
			// enable tcp keepalive since ssl connections typically do a lot of back/forth
			c.SetKeepAlive(true)
			c.SetKeepAlivePeriod(3 * time.Minute)

			r.HandleConn(c)
		}
	}
}

// PushConn allows pushing an existing connection to the queue as if it had
// just been accepted by the server. No auto-detection will be performed.
func (r *Listener) PushConn(c net.Conn) {
	r.queue <- queuePoint{c: c}
}

// HandleConn will run detection on a given incoming connection and attempt to
// find if it should parse any kind of PROXY headers, or TLS handshake/etc.
func (r *Listener) HandleConn(c net.Conn) {
	r.thCntLock.Lock()
	if r.thCnt >= r.thMax {
		// out of luck
		r.thCntLock.Unlock()
		c.Close()
		return
	}
	r.thCnt += 1
	r.thCntLock.Unlock()

	go r.processFilters(c)
}

func (p *Listener) String() string {
	return p.addr.String()
}
