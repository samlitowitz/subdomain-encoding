package subdomain_encoding

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
	"time"
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
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5 * time.Second))
		rawUrl, err := readRawUrl(ctx, r, be.topLevelDomain)
		cancel()
		if err != nil {
			return err
		}
		// split into subdomains
		subdomains := strings.Split(rawUrl[:len(rawUrl)-len(be.topLevelDomain)], ".")
		// foreach subdomain
		for _, subdomain := range subdomains {
			//    base32 decode
			decodedReader := base32.NewDecoder(base32.StdEncoding.WithPadding(base32.NoPadding), bytes.NewReader([]byte(subdomain)))
			//    read until io.EOF
			//    decrypt
			//    emit
		}
	}
}

func readRawUrl(ctx context.Context, r io.Reader, topLevelDomain string) (string, error) {
	rawUrl := make([]byte, 0, MaxDomainNameLength)
	for ; ; {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		_, err := r.Read(rawUrl[len(rawUrl):])
		if err != nil {
			return "", err
		}

		// not enough characters to hold top level domain, do not check if it contains
		if len(rawUrl) < len(topLevelDomain) {
			continue
		}

		// at max length length and does not include top level domain
		if len(rawUrl) >= MaxDomainNameLength && !strings.Contains(string(rawUrl), topLevelDomain) {
			return "", fmt.Errorf("top level domain `%s` not found in raw URL `%s`", topLevelDomain, rawUrl)
		}

		// does not include top level domain
		if !strings.Contains(string(rawUrl), topLevelDomain) {
			continue
		}

		return string(rawUrl), nil
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
		encodingInputWriter := base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), encodedOutputWriter)
		n, err = encodingInputWriter.Write(encrypted)
		if err != nil {
			return err
		}
		if n != len(encrypted) {
			return fmt.Errorf("failed to encode all data")
		}

		encodedOutputWriter.Reset()
		subdomain.Reset()
		// build subdomain
	build_subdomain:
		for remainingDomainNameLength := MaxDomainNameLength - len(be.topLevelDomain); remainingDomainNameLength > 0; {
			for i := 0; i < be.maxSubdomainLevels; i++ {
				nextSubdomainMaxLength := min(MaxSubdomainNameLength, remainingDomainNameLength)
				encoded := encodedOutputWriter.Next(nextSubdomainMaxLength)
				if len(encoded) == 0 {
					break
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
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
