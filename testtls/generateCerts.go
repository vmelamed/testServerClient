package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const showCertCmdFmt = "# %s\necho \"%s\" | openssl x509 -text -noout\n"

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func makePublicPrivateKey(privKeyID string) (publicKey, privateKey interface{}, pubKeyID []byte, err error) {
	switch privKeyID {
	case "P256":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ECDSA":
		fallthrough
	case "P521":
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "RSA":
		fallthrough
	case "RSA2048":
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA4096":
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ED25519":
		fallthrough
	case "EDDSA":
		fallthrough
	case "X25519":
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = fmt.Errorf("don't know how to make public/private key %s", privKeyID)
	}
	if err != nil {
		return
	}

	switch privKeyID {
	case "ECDSA":
		fallthrough
	case "P256":
		fallthrough
	case "P384":
		fallthrough
	case "P521":
		publicKey = privateKey.(*ecdsa.PrivateKey).Public()
	case "RSA":
		fallthrough
	case "RSA2048":
		fallthrough
	case "RSA4096":
		publicKey = privateKey.(*rsa.PrivateKey).Public()
	case "ED25519":
		fallthrough
	case "EDDSA":
		fallthrough
	case "X25519":
		publicKey = privateKey.(ed25519.PrivateKey).Public()
	}

	pubKeyID, err = makePublicKeyID(publicKey)
	if err != nil {
		privateKey = nil
		publicKey = nil
	}
	return
}

func makePublicKeyID(publicKey interface{}) (pubKeyID []byte, err error) {
	encodedPubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}

	var subPKI subjectPublicKeyInfo

	_, err = asn1.Unmarshal(encodedPubBytes, &subPKI)
	if err != nil {
		return
	}

	pubKeySum := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	pubKeyID = pubKeySum[:]
	return
}

func generateCerts(privKeyID string) (serverCert *tls.Certificate, caCert *x509.Certificate, err error) {
	maxSerialNumber := new(big.Int).SetBits([]big.Word{0, 0, 1}) // 2^129

	// create CA certificate
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return
	}

	publicKeyCA, privateKeyCA, _, err := makePublicPrivateKey(privKeyID)
	if err != nil {
		return
	}

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
		DNSNames:              []string{"test-ca"},
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDERBytes, err := x509.CreateCertificate(rand.Reader, templateCA, templateCA, publicKeyCA, privateKeyCA)
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

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKeyCA)
	if err != nil {
		return
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	ioutil.WriteFile("certs/ca-key-g.pem", keyPEMBytes, os.FileMode(0644))

	// create server certificate
	serialNumber, err = rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		caCert = nil
		return
	}

	publicKey, privateKey, _, err := makePublicPrivateKey(privKeyID)
	if err != nil {
		return
	}

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
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, templateServer, caCert, publicKey, privateKeyCA)
	if err != nil {
		caCert = nil
		return
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDERBytes,
	})
	ioutil.WriteFile("certs/server-cert-g.pem", certPEMBytes, os.FileMode(0644))
	keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}
	keyPEMBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	ioutil.WriteFile("certs/server-key-g.pem", keyPEMBytes, os.FileMode(0644))

	cert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		caCert = nil
		return
	}

	serverCert = &tls.Certificate{
		Certificate: [][]byte{certDERBytes, caCertDERBytes},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return
}
