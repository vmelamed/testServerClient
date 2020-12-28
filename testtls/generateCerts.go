package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const showCertCmdFmt = "# %s\necho \"%s\" | openssl x509 -text -noout\n"

func generateCerts() (serverCert *tls.Certificate, caCert *x509.Certificate, err error) {
	maxSerialNumber := new(big.Int).SetBits([]big.Word{0, 0, 1}) // 2^129

	// create CA certificate
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return
	}

	// _, privKey, _ := ed25519.GenerateKey(rand.Reader)
	// privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	pubKeyBytes, err := asn1.Marshal(*privKey.Public().(*rsa.PublicKey))
	if err != nil {
		return
	}
	caSubjectKeyID := sha1.Sum(pubKeyBytes)

	templateCA := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test-ca",
			Organization: []string{"test ca"},
			Country:      []string{"USA"},
			Province:     []string{"NY"},
			Locality:     []string{"New York City"},
		},
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          caSubjectKeyID[:],
		DNSNames:              []string{"test-ca"},
		KeyUsage:              x509.KeyUsageCertSign, // x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment |
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	caCertDERBytes, err := x509.CreateCertificate(rand.Reader, templateCA, templateCA, privKey.Public(), privKey)
	if err != nil {
		return
	}

	caCert, err = x509.ParseCertificate(caCertDERBytes)
	if err != nil {
		return
	}

	caCertPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDERBytes,
	})
	ioutil.WriteFile("certs/ca-cert-g.pem", caCertPEMBytes, os.FileMode(0644))

	// create server certificate
	serialNumber, err = rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		caCert = nil
		return
	}

	// _, privKey, _ := ed25519.GenerateKey(rand.Reader)
	// privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		caCert = nil
		return
	}

	pubKeyBytes, err = asn1.Marshal(*privKey.Public().(*rsa.PublicKey))
	if err != nil {
		return
	}
	servSubjectKeyID := sha1.Sum(pubKeyBytes)

	templateServer := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Server"},
			Country:      []string{"USA"},
			Province:     []string{"NY"},
			Locality:     []string{"New York City"},
		},
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		BasicConstraintsValid: true,
		SubjectKeyId:          servSubjectKeyID[:],
		AuthorityKeyId:        caSubjectKeyID[:],
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // , x509.ExtKeyUsageClientAuth
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, templateServer, caCert, privKey.Public(), privKey)
	if err != nil {
		caCert = nil
		return
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDERBytes,
	})
	ioutil.WriteFile("certs/server-cert-g.pem", certPEMBytes, os.FileMode(0644))

	cert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		caCert = nil
		return
	}

	serverCert = &tls.Certificate{
		Certificate: [][]byte{certDERBytes, caCertDERBytes},
		PrivateKey:  privKey,
		Leaf:        cert,
	}

	return
}
