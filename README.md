# MagicTLS

[![Build Status](https://github.com/KarpelesLab/magictls/workflows/Go/badge.svg)](https://github.com/KarpelesLab/magictls/actions)
[![GoDoc](https://godoc.org/github.com/KarpelesLab/magictls?status.svg)](https://godoc.org/github.com/KarpelesLab/magictls)

A Go library that provides automatic protocol detection for TCP connections, enabling a single port to handle multiple protocols transparently.

## Features

- **Automatic TLS Detection**: Distinguishes between TLS/SSL and plaintext connections on the same port
- **PROXY Protocol Support**: Detects both PROXY v1 and v2 headers to extract real client IPs (essential for load balancers like AWS ELB, Google Cloud LB)
- **Protocol Routing**: Routes connections to different handlers based on TLS-negotiated protocols (ALPN)
- **Extensible Filter System**: Add custom protocol detection with the Filter interface
- **Zero External Dependencies**: Uses only the Go standard library

## Installation

```bash
go get github.com/KarpelesLab/magictls
```

## Requirements

This library works with protocols where:
- The **client sends the first data** (not the server)
- The client sends **at least 16 bytes** initially

Works well with: HTTP, TLS/SSL, WebSocket, gRPC

May not work with: POP3, IMAP, SMTP (server speaks first) - unless using `ForceTLS` filter

## Quick Start

### Basic Usage

Replace `tls.Listen()` with `magictls.Listen()` for automatic protocol detection:

```go
package main

import (
    "log"
    "net/http"

    "github.com/KarpelesLab/magictls"
)

func main() {
    // Create TLS config
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    // Create listener with automatic TLS detection
    socket, err := magictls.Listen("tcp", ":8080", tlsConfig)
    if err != nil {
        log.Fatal(err)
    }

    // Use with standard http.Server
    log.Fatal(http.Serve(socket, handler))
}
```

Both HTTP and HTTPS requests on port 8080 will be handled automatically.

### Force TLS Only

To require TLS while still supporting PROXY protocol:

```go
socket, err := magictls.Listen("tcp", ":8443", tlsConfig)
if err != nil {
    log.Fatal(err)
}
socket.Filters = []magictls.Filter{magictls.DetectProxy, magictls.ForceTLS}
```

### Protocol-Specific Listeners (ALPN)

Route connections based on TLS-negotiated protocols:

```go
// Configure TLS with supported protocols
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    NextProtos:   []string{"h2", "http/1.1", "my-protocol"},
}

socket, err := magictls.Listen("tcp", ":443", tlsConfig)
if err != nil {
    log.Fatal(err)
}

// Create listener for custom protocol
myProtoListener, err := socket.ProtoListener("my-protocol")
if err != nil {
    log.Fatal(err)
}

// Handle custom protocol connections
go func() {
    for {
        conn, err := myProtoListener.Accept()
        if err != nil {
            return
        }
        go handleMyProtocol(conn)
    }
}()

// Main listener handles remaining connections (h2, http/1.1)
log.Fatal(http.Serve(socket, handler))
```

## PROXY Protocol Configuration

### Default Allowed Proxies

By default, only private/local IPs are trusted to send PROXY headers:
- `127.0.0.0/8` (localhost)
- `10.0.0.0/8` (private)
- `172.16.0.0/12` (private)
- `192.168.0.0/16` (private)
- `::1/128` (IPv6 localhost)
- `fd00::/8` (IPv6 private)

### Adding Cloud Load Balancer IPs

#### Google Cloud

```go
magictls.AddAllowedProxies("35.191.0.0/16", "130.211.0.0/22")
// Or use SPF records for automatic discovery:
magictls.AddAllowedProxiesSpf("_cloud-eoips.googleusercontent.com")
```

#### AWS (Custom ranges)

```go
magictls.AddAllowedProxies("10.0.0.0/8") // Your VPC CIDR
```

#### Reset to Custom List

```go
magictls.SetAllowedProxies("10.0.0.0/8", "172.16.0.0/12")
```

## Custom Filters

Implement custom protocol detection by creating a Filter function:

```go
func MyProtocolFilter(conn *magictls.Conn, srv *magictls.Listener) error {
    // Peek at first 4 bytes without consuming them
    buf, err := conn.PeekUntil(4)
    if err != nil {
        return err
    }

    // Check for custom protocol magic bytes
    if bytes.Equal(buf, []byte("MYCL")) {
        // Skip the magic bytes
        conn.SkipPeek(4)
        // Return Override to signal protocol was detected
        return &magictls.Override{Protocol: "my-protocol"}
    }

    return nil // Not our protocol, continue to next filter
}

// Use the custom filter
socket.Filters = []magictls.Filter{
    magictls.DetectProxy,
    MyProtocolFilter,
    magictls.DetectTLS,
}
```

## Integration with autocert

For automatic Let's Encrypt certificates:

```go
import "golang.org/x/crypto/acme/autocert"

m := &autocert.Manager{
    Prompt:     autocert.AcceptTOS,
    HostPolicy: autocert.HostWhitelist("example.com", "www.example.com"),
    Cache:      autocert.DirCache("/var/cache/autocert"),
}

cfg := m.TLSConfig()
cfg.NextProtos = append(cfg.NextProtos, "my-protocol") // Add custom protocols

socket, err := magictls.Listen("tcp", ":443", cfg)
if err != nil {
    log.Fatal(err)
}

log.Fatal(http.Serve(socket, handler))
```

## API Reference

### Main Types

- `Listener` - The main listener that accepts connections and runs filters
- `Conn` - Connection wrapper with peek/unread support for protocol detection
- `Filter` - Function type for protocol detection: `func(*Conn, *Listener) error`
- `Override` - Special error type returned by filters to signal connection changes

### Built-in Filters

- `DetectProxy` - Detects PROXY v1/v2 headers and updates connection addresses
- `DetectTLS` - Auto-detects TLS/SSL vs plaintext connections
- `ForceTLS` - Requires TLS handshake (no plaintext support)

### Key Functions

- `Listen(network, addr, tlsConfig)` - Create a new listener
- `ListenNull()` - Create a listener without binding (for custom use with PushConn)
- `SetAllowedProxies(cidrs...)` - Set allowed PROXY protocol source IPs
- `AddAllowedProxies(cidrs...)` - Add to allowed PROXY protocol source IPs
- `GetTlsConn(conn)` - Extract *tls.Conn from wrapped connections

## Thread Safety

The library is thread-safe. Multiple goroutines can:
- Accept connections from the same listener
- Modify allowed proxy IPs (with proper synchronization)
- Use protocol-specific listeners concurrently

## License

MIT License - see LICENSE file for details.

## Contributing

Pull requests welcome! Please ensure tests pass with `go test ./...`.
