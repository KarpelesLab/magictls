# MagicTLS

A simple Go library that detects protocol and does various things for you.

[Documentation](https://godoc.org/github.com/MagicalTux/magictls)

## Usage

Use magictls.Listen() to create sockets.

	socket, err := magictls.Listen("tcp", ":8080", tlsConfig)
	if err != nil {
		...
	}
	log.Fatal(http.Serve(socket, handler))

