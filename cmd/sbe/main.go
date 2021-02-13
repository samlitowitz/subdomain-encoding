package main

import (
	"crypto/aes"
	"flag"
	"fmt"
	"github.com/samlitowitz/subdomain-block-encoding/pkg/subdomain_encoding"
	"log"
	"os"
)

func main() {
	var  domain, key string

	flag.StringVar(&domain, "domain", "", "Top level domain")
	flag.StringVar(&key, "key", "", "AES key")
	flag.Parse()

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	encoder := subdomain_encoding.NewBlockCipherEncoder(domain, 1, cipher)
	subdomains, errors := encoder.Encode(os.Stdin)

	for ; ; {
		select {
		case subdomain := <-subdomains:
			fmt.Printf("%s%s\n", subdomain, domain)
		case err := <-errors:
			log.Fatal(err)
		}
	}
}