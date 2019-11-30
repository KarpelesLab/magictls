package magictls

type Filter func(conn *Conn, srv *MagicListener) error
