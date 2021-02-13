package subdomain_encoding

import "io"

const (
	MaxDomainNameLength int = 256
	MaxSubdomainNameLength int = 63
)

type Encoder interface {
	Decode(io.Reader) (<-chan string, <-chan error)
	Encode(io.Reader) (<-chan string, <-chan error)
}