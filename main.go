package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func main() {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	emailAddress := "myemail@domain.com"

	subj := pkix.Name{
		CommonName:         "*.domain.com",
		Country:            []string{"US"},
		Province:           []string{"State"},
		Locality:           []string{"City"},
		Organization:       []string{"Company"},
		OrganizationalUnit: []string{"Technology Group"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		DNSNames:           []string{"*.domain.com", "domain.com"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)

	//  Print Private Key to a file  //
	keyOut, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("failed to open ca.key for writing:", err)
		os.Exit(1)
	}

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})
	keyOut.Close()

	//   Print Certificate Request to a file  //
	csrOut, err := os.OpenFile("ca.csr", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("failed to open ca.csr for writing:", err)
		os.Exit(1)
	}

	(pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}))
	csrOut.Close()

	//  Print Private key to stdout //
	pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})

	// Print Certificate Requeat to stdout //
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

}
