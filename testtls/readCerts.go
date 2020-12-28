package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

func readCerts(serverCertFile string, serverKeyFile string, caCertFile string) (serverCert *tls.Certificate, caCert *x509.Certificate, err error) {
	file1, err := os.Open(serverCertFile)
	if err != nil {
		return
	}
	defer file1.Close()

	pemCert, err := ioutil.ReadAll(file1)
	if err != nil {
		return
	}

	file2, err := os.Open(serverKeyFile)
	if err != nil {
		return
	}
	defer file2.Close()

	pemKey, err := ioutil.ReadAll(file2)
	if err != nil {
		return
	}

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		err = errors.Wrap(err, "error loading server certificate and key")
		return
	}
	block, _ := pem.Decode(pemCert)
	c, err := x509.ParseCertificate(block.Bytes)
	cert.Leaf = c
	serverCert = &cert

	bytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		err = errors.Wrap(err, "error reading CA certificate")
		return
	}

	block, _ = pem.Decode(bytes)
	if block == nil {
		err = errors.New("error decoding CA certificate PEM")
		return
	}

	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = errors.Wrap(err, "error parcing CA certificate")
		return
	}
	return
}
