package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"
)

func main() {
	var tlsSrvCert *tls.Certificate
	var caCert *x509.Certificate
	var err error

	fmt.Println("TEST WITH GENERATED CERTIFICATES")
	tlsSrvCert, caCert, err = generateCerts()
	if err != nil {
		err = errors.Wrap(err, "error generating certificates")
	} else {
		err = testClientServer(tlsSrvCert, caCert)
	}
	if err == nil {
		fmt.Print("Success in Client-Server test with generated certificates\n")
	} else {
		fmt.Printf("Error in Client-Server test with generated certificates: %+v\n", err)
	}

	fmt.Println("TEST WITH FILE CERTIFICATES")
	tlsSrvCert, caCert, err = readCerts("certs/server-cert.pem", "certs/server-key.pem", "certs/ca-cert.pem")
	if err != nil {
		err = errors.Wrap(err, "error reading certificates")
	} else {
		err = testClientServer(tlsSrvCert, caCert)
	}
	if err == nil {
		fmt.Print("Success in Client-Server test with certificates from files\n")
	} else {
		fmt.Printf("Error in Client-Server test with certificates from files: %+v\n", err)
	}
}
