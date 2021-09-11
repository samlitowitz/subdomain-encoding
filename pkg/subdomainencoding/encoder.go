package subdomainencoding

// Encoder is an interface for which can be implemented by and sub-domain encoder allowing the ability to swap between different encoding strategies
type Encoder interface {
	Decode(src []byte) ([]byte, error)
	Encode(src []byte) (string, error)
}