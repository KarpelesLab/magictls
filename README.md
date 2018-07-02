# MagicTLS

A simple Go library that detects protocol automatically:

* Support for PROXY and PROXYv2 allows detecting the real user's IP when, for example, [using AWS elastic load balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-proxy-protocol.html). The fact the protocol is detected automatically allows the daemon to work even before ELB is properly configured, and avoid rejecting requests by mistake.
* Automatic TLS support allows using a single port for SSL and non-SSL traffic, and simplifies configuration.

This library was used in some of my projects, I've cleaned it up and licensed it under the MIT License since it's small and useful. Pull requests welcome.

[Documentation](https://godoc.org/github.com/MagicalTux/magictls)

## Usage

Use magictls.Listen() to create sockets.

	socket, err := magictls.Listen("tcp", ":8080", tlsConfig)
	if err != nil {
		...
	}
	log.Fatal(http.Serve(socket, handler))

