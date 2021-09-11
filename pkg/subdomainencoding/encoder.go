package subdomainencoding

import "io"

const (
	MaxDomainNameLength int = 253
	MaxSubdomainNameLength int = 63
)

type Encoder interface {
	Decode(io.Reader) (<-chan string, <-chan error)
	Encode(io.Reader) (<-chan string, <-chan error)
}