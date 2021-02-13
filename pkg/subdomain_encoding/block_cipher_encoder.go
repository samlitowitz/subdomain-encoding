package subdomain_encoding

import (
	"bytes"
	"crypto/cipher"
	"encoding/base32"
	"fmt"
	"io"
)

const Terminator = 0xa

type BlockCipherEncoder struct {
	block              cipher.Block
	topLevelDomain     string
	maxSubdomainLevels int
}

func NewBlockCipherEncoder(topLevelDomain string, maxSubdomainLevels int, block cipher.Block) *BlockCipherEncoder {
	return &BlockCipherEncoder{
		block:              block,
		topLevelDomain:     topLevelDomain,
		maxSubdomainLevels: maxSubdomainLevels,
	}
}

func (be *BlockCipherEncoder) Decode(r io.Reader) (<-chan string, <-chan error) {
	output := make(chan string, 1)
	errors := make(chan error, 1)

	go func() {
		err := be.decodeInput(r, output)
		if err != nil {
			close(output)
			errors <- err
		}
	}()
	return output, errors
}

func (be *BlockCipherEncoder) Encode(r io.Reader) (<-chan string, <-chan error) {
	output := make(chan string, 1)
	errors := make(chan error, 1)

	go func() {
		err := be.encodeInput(r, output)
		if err != nil {
			close(output)
			errors <- err
		}
	}()
	return output, errors
}

func (be *BlockCipherEncoder) decodeInput(r io.Reader, output chan<- string) error {
	for ; ; {
		// read url
		//    read until terminator or max
		// strip top level domain
		// split into subdomains
		// foreach subdomain
		//    base32 decode
		//    decrypt
		//    emit
	}
}

func (be *BlockCipherEncoder) encodeInput(r io.Reader, output chan<- string) error {
	blockSize := be.block.BlockSize()
	src := make([]byte, blockSize)
	encrypted := make([]byte, blockSize)
	encodedOutputWriter := bytes.NewBuffer(make([]byte, (len(encrypted)*8/5)+1))
	subdomain := bytes.NewBuffer(make([]byte, MaxDomainNameLength-len(be.topLevelDomain)))
	for ; ; {
		// read at most blockSize bytes
		n, err := r.Read(src)
		if err != nil {
			return err
		}
		// pad data to block size
		for i := 0; i < blockSize-n; i++ {
			src = append(src, 0)
		}
		// encrypt data
		be.block.Encrypt(encrypted, src)
		// base32 encode
		encodingInputWriter := base32.NewEncoder(base32.StdEncoding, encodedOutputWriter)
		n, err = encodingInputWriter.Write(encrypted)
		if err != nil {
			return err
		}
		if n != len(encrypted) {
			return fmt.Errorf("failed to encode all data")
		}

		// build subdomain
		subdomain.Reset()
	build_subdomain:
		for remainingDomainNameLength := MaxDomainNameLength - len(be.topLevelDomain); remainingDomainNameLength > 0; {
			for i := 0; i < be.maxSubdomainLevels; i++ {
				nextSubdomainMaxLength := min(MaxSubdomainNameLength, remainingDomainNameLength)
				encoded := encodedOutputWriter.Next(nextSubdomainMaxLength)
				if len(encoded) == 0 {
					break
				}

				// strip padding
				j := bytes.IndexByte(encoded, '=')
				if j > -1 {
					encoded = encoded[:j]
				}

				subdomain.Write(encoded)
				subdomain.Write([]byte("."))

				if len(encoded) < nextSubdomainMaxLength {
					break build_subdomain
				}
				remainingDomainNameLength = remainingDomainNameLength - nextSubdomainMaxLength - 1
			}
		}
		output <- subdomain.String()
		// clear slices
		src = src[:0]
		encrypted = encrypted[:0]
		encodedOutputWriter.Reset()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
