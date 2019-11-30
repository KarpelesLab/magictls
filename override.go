package magictls

import "net"

// special type returned as error by filters to return a different Conn
type Override struct {
	net.Conn
}

func (o *Override) Error() string {
	return "Connection override required"
}
