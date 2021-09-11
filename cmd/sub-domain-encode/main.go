package main

import (
	"crypto/aes"
	"flag"
	"fmt"
	"github.com/samlitowitz/subdomain-block-encoding/pkg"
	"github.com/samlitowitz/subdomain-block-encoding/pkg/subdomain_encoding"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	var domain, key string

	flag.StringVar(&domain, "domain", "", "Top level domain")
	flag.StringVar(&key, "key", "", "AES key")
	flag.Parse()

	domainName := pkg.NewDomainName()
	subDomains := strings.Split(domain, ".")
	for _, subDomain := range subDomains {
		domainName.AddSubDomain(subDomain)
	}

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	encoder := subdomainencoding.NewBlockCipherEncoder(domainName, cipher)
	buf := make([]byte, 0, encoder.MaxBytes())
	for {
		n, err := os.Stdin.Read(buf)
		if err == io.EOF {
			output, err := encoder.Encode(buf[:n])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(output)
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		output, err := encoder.Encode(buf[:n])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(output)
	}
}
