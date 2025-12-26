package magictls

import (
	"io"
	"net"
)

// protoListener is a net.Listener implementation that receives connections
// for specific TLS ALPN-negotiated protocols. It is created by calling
// Listener.ProtoListener with one or more protocol names.
type protoListener struct {
	proto  []string         // registered protocol names
	queue  chan *queuePoint // incoming connection queue
	parent *Listener        // parent listener
}

// Accept waits for and returns the next connection to the listener.
// Connections returned here have completed TLS handshake and negotiated
// one of the protocols registered for this listener.
func (p *protoListener) Accept() (net.Conn, error) {
	pc, ok := <-p.queue
	if !ok {
		return nil, io.EOF
	}

	return pc.c, pc.e
}

// Addr returns the listener's network address.
func (p *protoListener) Addr() net.Addr {
	return p.parent.Addr()
}

// Close closes the protocol listener and unregisters it from the parent.
// Any blocked Accept calls will return io.EOF.
func (p *protoListener) Close() error {
	if p.queue == nil {
		return nil
	}

	// remove self
	p.parent.protoLk.Lock()
	defer p.parent.protoLk.Unlock()

	for _, proto := range p.proto {
		delete(p.parent.proto, proto)
	}

	// we can close p.queue here because we have the lock
	close(p.queue)
	p.queue = nil
	return nil
}
