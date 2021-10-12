package magictls

import "net"

// special type returned as error by filters to return a different Conn
type Override struct {
	Conn     net.Conn
	Protocol string
}

func (o *Override) Error() string {
	return "Connection override required"
}
