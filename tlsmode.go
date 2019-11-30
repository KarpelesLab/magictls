package magictls

type TLSMode int

const (
	Auto   TLSMode = iota // Auto tls mode means tls will be enabled if connection looks tls
	Always                // this will always attempt to perform TLS handshake
	Never                 // never do the TLS handshake
)
