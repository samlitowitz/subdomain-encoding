package subdomainencoding_test

import (
	"crypto/aes"
	"encoding/hex"
	"github.com/samlitowitz/subdomain-encoding/pkg"
	"github.com/samlitowitz/subdomain-encoding/pkg/subdomainencoding"
	"testing"
)

func TestBlockCipherEncoder_Decode(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	dn := pkg.NewDomainName()
	dn.AddSubDomain("com")
	dn.AddSubDomain("test")
	bce := subdomainencoding.NewBlockCipherEncoder(dn, cipher)

	testPhrase := "Hello World!"
	plainText := make([]byte, len(testPhrase))
	copy(plainText, testPhrase)
	encodedOutput, err := bce.Encode(plainText)
	if err != nil {
		t.Fatal(err)
	}

	cipherText := make([]byte, len(encodedOutput))
	copy(cipherText, encodedOutput)

	decodedOutput, err := bce.Decode(cipherText)
	if err != nil {
		t.Fatal(err)
	}

	if string(decodedOutput) != string(plainText) {
		t.Fatalf("`%s` did not match expected `%s`", decodedOutput, plainText)
	}
}