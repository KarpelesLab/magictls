package magictls

import (
	"io"
	"net"
)

type protoListener struct {
	proto  []string
	queue  chan *queuePoint
	parent *Listener
}

func (p *protoListener) Accept() (net.Conn, error) {
	pc, ok := <-p.queue
	if !ok {
		return nil, io.EOF
	}

	return pc.c, pc.e
}

func (p *protoListener) Addr() net.Addr {
	return p.parent.Addr()
}

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
