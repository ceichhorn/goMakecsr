package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func main() {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	emailAddress := "SSL-Management@domain.com"
	// SAN := "star.gannett.com, test.gannett.com"
	subj := pkix.Name{
		CommonName:         "*.domain.com",
		Country:            []string{"US"},
		Province:           []string{"Virginia"},
		Locality:           []string{"Chesapeake"},
		Organization:       []string{"Company"},
		OrganizationalUnit: []string{"Technology Operations"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	template.DNSNames = []string{"star.domain.com", "test.domain.com", "www.domain.com"}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

}
