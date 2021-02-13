package subdomain_encoding

import "io"

const (
	MaxDomainNameLength int = 256
	MaxSubdomainNameLength int = 63
)

type Encoder interface {
	Encode(io.Reader) (<-chan string, error)
}