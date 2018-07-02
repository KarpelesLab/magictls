package magictls

import (
	"crypto/tls"
	"errors"
	"log"
)

func retrieveTlsCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if clientHello.ServerName == "" {
		return nil, errors.New("http: SSL handshake refused because missing SNI")
	}

	log.Printf("[debug] Client hello - SNI=%s", clientHello.ServerName)
	return nil, errors.New("nope")
}
