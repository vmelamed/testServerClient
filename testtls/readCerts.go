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
	// read the caCertFile PEM
	bytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		err = errors.Wrap(err, "error reading CA certificate")
		return
	}

	caPEMBlock, _ := pem.Decode(bytes)
	if caPEMBlock == nil {
		err = errors.New("error decoding CA certificate PEM")
		return
	}
	if caPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("error in CA PEM contents")
		return
	}

	// read the server cert and key PEMs to parse them into tls.Certificate
	fileCert, err := os.Open(serverCertFile)
	if err != nil {
		return
	}
	defer fileCert.Close()
	pemCert, err := ioutil.ReadAll(fileCert)
	if err != nil {
		return
	}

	fileKey, err := os.Open(serverKeyFile)
	if err != nil {
		return
	}
	defer fileKey.Close()
	pemKey, err := ioutil.ReadAll(fileKey)
	if err != nil {
		return
	}

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		err = errors.Wrap(err, "error loading server certificate and key")
		return
	}
	// append the CA to the server cert chain
	cert.Certificate = append(cert.Certificate, caPEMBlock.Bytes)

	// parse the cert PEM to fill the leaf
	servPEMBlock, _ := pem.Decode(pemCert)
	c, err := x509.ParseCertificate(servPEMBlock.Bytes)
	cert.Leaf = c
	serverCert = &cert

	caCert, err = x509.ParseCertificate(caPEMBlock.Bytes)
	if err != nil {
		err = errors.Wrap(err, "error parcing CA certificate")
		serverCert = nil
		return
	}

	return
}
