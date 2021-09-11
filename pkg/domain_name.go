package pkg

import (
	"fmt"
	"strings"
)

const (
	// MaxDomainNameLength is the maximum length of a domain name
	MaxDomainNameLength int = 253
	// MaxSubdomainNameLength is the maximum length of an individual sub-domain
	MaxSubdomainNameLength int = 63
)

// InvalidLabelError is for errors related to invalid labels
type InvalidLabelError struct {
	label string
}

func (err *InvalidLabelError) Error() string {
	return fmt.Sprintf("invalid label `%s`", err.label)
}

// InvalidDomainNameError is for errors related to invalid domain names
type InvalidDomainNameError struct {
	domainName string
}

func (err *InvalidDomainNameError) Error() string {
	return fmt.Sprintf("invalid label `%s`", err.domainName)
}

// DomainName represents a domain name
type DomainName struct {
	names []string
}

// NewDomainName creates a new DomainName
func NewDomainName() *DomainName {
	return &DomainName{
		names: make([]string, 0),
	}
}

// AddSubDomain adds a sub-domain to the domain name
func (dn *DomainName) AddSubDomain(subDomain string) error {
	if len(subDomain) < 1 || len(subDomain) > MaxSubdomainNameLength {
		return &InvalidLabelError{label: subDomain}
	}

	newDomainName := strings.Join(dn.names, ".") + "." + subDomain
	if len(newDomainName) > MaxDomainNameLength {
		return &InvalidDomainNameError{domainName: newDomainName}
	}

	dn.names = append(dn.names, subDomain)
	return nil
}

// Copy creates a copy of the domain name
func (dn *DomainName) Copy() (*DomainName, error) {
	output := NewDomainName()
	for _, label := range dn.names {
		err := output.AddSubDomain(label)
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}

// SetTopLevelDomain sets the top level domain
func (dn *DomainName) SetTopLevelDomain(tld string) error {
	if len(tld) < 1 || len(tld) > MaxSubdomainNameLength {
		return &InvalidLabelError{label: tld}
	}

	if len(dn.names) < 1 {
		dn.names = append(dn.names, tld)
		return nil
	}

	newDomainName := tld + "." + strings.Join(dn.names[1:], ".")
	if len(newDomainName) > MaxDomainNameLength {
		return &InvalidDomainNameError{domainName: newDomainName}
	}
	dn.names[0] = tld
	return nil
}

func (dn *DomainName) String() string {
	reversed := make([]string, len(dn.names))
	copy(reversed, dn.names)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return strings.Join(reversed, ".")
}
