package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
)

func readCerts(serverCertFile string, serverKeyFile string, caCertFile string) (serverCert *tls.Certificate, caCert *x509.Certificate, err error) {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	serverCert = &cert
	if err != nil {
		err = errors.Wrap(err, "error loading server certificate and key")
		return
	}

	bytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		err = errors.Wrap(err, "error reading CA certificate")
		return
	}

	block, _ := pem.Decode(bytes)
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
