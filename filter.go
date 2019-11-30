package magictls

type Filter func(conn *Conn, srv *Listener) error
