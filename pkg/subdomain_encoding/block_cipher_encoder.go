package subdomain_encoding

import (
	"bytes"
	"crypto/cipher"
	"encoding/base32"
	"fmt"
	"github.com/samlitowitz/subdomain-block-encoding/pkg"
	"strings"
)

// BlockCipherEncoder can encode or decode data using a block cipher into a domain name
type BlockCipherEncoder struct {
	block      cipher.Block
	domainName *pkg.DomainName
}

// NewBlockCipherEncoder creates a new BlockCipherEncoder
func NewBlockCipherEncoder(domainName *pkg.DomainName, block cipher.Block) *BlockCipherEncoder {
	return &BlockCipherEncoder{
		block:      block,
		domainName: domainName,
	}
}

// Decode takes a domain name which contains a message encoded using a block cipher
func (be *BlockCipherEncoder) Decode(src []byte) ([]byte, error) {
	blockSize := be.block.BlockSize()
	if blockSize > MaxSubdomainNameLength {
		return nil, fmt.Errorf("block size of %d is larger than maximum allowed sub-domain length of %d", blockSize, MaxSubdomainNameLength)
	}

	// 1. Remove base domain
	i := strings.LastIndex(string(src), be.domainName.String())
	if i != len(src)-len(be.domainName.String()) {
		return nil, fmt.Errorf("unable to strip shared domain name from source")
	}
	encodedCipherText := stripByte(src[:i], '.')

	// 1. Decode
	cipherText, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(encodedCipherText))
	if err != nil {
		return nil, err
	}

	// 1. Decrypt
	for i := 0; i < len(cipherText); i += blockSize {
		be.block.Decrypt(cipherText[i:], cipherText[i:])
	}
	plainText := cipherText

	// 1. Unpad
	unPaddedPlainText, err := pkcs7Unpad(plainText, blockSize)
	if err != nil {
		return nil, err
	}
	return unPaddedPlainText, nil
}

// Encode encodes data into a domain name using a block cipher
func (be *BlockCipherEncoder) Encode(src []byte) (string, error) {
	blockSize := be.block.BlockSize()
	if blockSize > MaxSubdomainNameLength {
		return "", fmt.Errorf("block size of %d is larger than maximum allowed sub-domain length of %d", blockSize, MaxSubdomainNameLength)
	}

	// 1. Pad
	plainText, err := pkcs7Pad(src, blockSize)
	if err != nil {
		return "", err
	}
	// 1. Encrypt
	for i := 0; i < len(plainText); i += blockSize {
		be.block.Encrypt(plainText[i:], plainText[i:])
	}
	cipherText := plainText

	// 1. Encode
	b32Output := bytes.NewBuffer(make([]byte, 0, len(cipherText)))
	b32Input := base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), b32Output)
	b32Input.Write(cipherText)
	b32Input.Close()
	encodedCipherText := make([]byte, b32Output.Len())
	n, err := b32Output.Read(encodedCipherText)
	if err != nil {
		return "", err
	}
	if n != len(encodedCipherText) {
		return "", fmt.Errorf("failed to encode all bytes")
	}

	// 1. Build sub-domain
	dn := be.domainName.Copy()
	for i := 0; i < len(encodedCipherText); {
		remainingCipherText := len(encodedCipherText) - i
		n := (MaxSubdomainNameLength / blockSize) * blockSize
		if remainingCipherText < n {
			n = remainingCipherText
		}
		err = dn.AddSubDomain(string(encodedCipherText[i:n]))
		if err != nil {
			return "", err
		}
		i += n
	}
	return dn.String(), nil
}

// MaxBytes is the maximum number of bytes that can be encoded into a single domain name taking the cipher block size and base domain name into account
func (be *BlockCipherEncoder) MaxBytes() int {
	blockSize := be.block.BlockSize()

	n := MaxDomainNameLength - len(be.domainName.String())
	maxBlocks := n / (blockSize + 1)
	if n % (blockSize + 1) > 0 {
		maxBlocks += 1
	}

	return maxBlocks * blockSize
}

func stripByte(src []byte, b byte) []byte {
	stripped := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		// skip the strip
		if src[i] == b {
			continue
		}
		stripped = append(stripped, src[i])
	}
	return stripped
}
