# MagicTLS

[![Build Status](https://github.com/MagicalTux/magictls/workflows/Go/badge.svg)](https://github.com/MagicalTux/magictls/actions)
[![GoDoc](https://godoc.org/github.com/MagicalTux/magictls?status.svg)](https://godoc.org/github.com/MagicalTux/magictls)

A simple Go library that detects protocol automatically:

* Support for PROXY and PROXYv2 allows detecting the real user's IP when, for example, [using AWS elastic load balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-proxy-protocol.html). The fact the protocol is detected automatically allows the daemon to work even before ELB is properly configured, and avoid rejecting requests by mistake.
* Automatic TLS support allows using a single port for SSL and non-SSL traffic, and simplifies configuration.

This library was used in some of my projects, I've cleaned it up and licensed it under the MIT License since it's small and useful. Pull requests welcome.

It is written to work with protocols where the client sends the first data, and it expects the client to send at least 16 bytes. This works nicely with HTTP (`GET / HTTP/1.0\r\n` is exactly 16 bytes), SSL, etc. but may not work with protocols such as POP3, IMAP or SMTP where the server is expected to send the first bytes unless TLS is required.

## Usage

Use `magictls.Listen()` to create sockets the same way you would use `tls.Listen()`.

	socket, err := magictls.Listen("tcp", ":8080", tlsConfig)
	if err != nil {
		...
	}
	log.Fatal(http.Serve(socket, handler))

The created listener can receive various configurations. For example if you need to force all connections to be TLS and only want to use PROXY protocol detection:

	socket, err := magictls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		...
	}
	socket.Filters = []magictls.Filter{magictls.DetectProxy, magictls.ForceTLS}
	log.Fatal(http.Serve(socket, handler))

It is also possible to implement your own filters.
