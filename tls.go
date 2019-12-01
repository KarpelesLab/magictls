package magictls

import "crypto/tls"

func DetectTLS(conn *Conn, srv *Listener) error {
	buf, err := conn.PeekUntil(1)
	if err != nil {
		return err
	}

	// perform auto-detection
	if buf[0]&0x80 == 0x80 {
		// SSLv2, probably. At least, not HTTP
		cs := tls.Server(conn, srv.TLSConfig)
		if err = cs.Handshake(); err != nil {
			// note: at this point we lost data, connection should be closed
			conn.Close()
			return err
		}
		return &Override{cs}
	}
	if buf[0] == 0x16 {
		// SSLv3, TLS
		cs := tls.Server(conn, srv.TLSConfig)
		if err = cs.Handshake(); err != nil {
			// note: at this point we lost data, connection should be closed
			conn.Close()
			return err
		}
		return &Override{cs}
	}

	// probably not tls
	return nil
}

func ForceTLS(conn *Conn, srv *Listener) error {
	cs := tls.Server(conn, srv.TLSConfig)
	if err := cs.Handshake(); err != nil {
		return err
	}
	return &Override{cs}
}
