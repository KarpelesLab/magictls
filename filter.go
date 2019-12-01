package magictls

// Filter is a generic magictls filter, to be used when accepting a connection.
// Default filters provided for convenience include DetectProxy, DetectTLS and
// ForceTLS.
type Filter func(conn *Conn, srv *Listener) error
