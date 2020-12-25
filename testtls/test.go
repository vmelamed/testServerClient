package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

const showCertCmdFmt = "echo \"%s\" | openssl x509 -text -noout\n"

func main() {
	// create CA certificate
	max := new(big.Int).SetBits([]big.Word{0, 0, 1}) // 2^129
	serialNumber, _ := rand.Int(rand.Reader, max)
	templateCA := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test-ca",
			Organization: []string{"Test CA"},
			Country:      []string{"USA"},
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // only for RSA keys: | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},        // x509.ExtKeyUsageClientAuth,
		DNSNames:              []string{"test-ca", "test-ca.io"},
	}
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	certBytes, _ := x509.CreateCertificate(rand.Reader, templateCA, templateCA, privKey.Public(), privKey)
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	fmt.Printf(showCertCmdFmt, string(caCertPEM))
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	tlsCert, _ := tls.X509KeyPair(caCertPEM, caKeyPEM)
	caCert, _ := x509.ParseCertificate(tlsCert.Certificate[0])

	// create server certificate
	serialNumber, _ = rand.Int(rand.Reader, max)
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Server"},
			Country:      []string{"USA"},
		},
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		KeyUsage:     x509.KeyUsageDigitalSignature,                  // only for RSA keys: | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // x509.ExtKeyUsageClientAuth,
		DNSNames:     []string{"localhost"},
	}
	_, privKey, _ = ed25519.GenerateKey(rand.Reader)
	certBytes, _ = x509.CreateCertificate(rand.Reader, template, caCert, privKey.Public(), privKey)
	keyBytes, _ = x509.MarshalPKCS8PrivateKey(privKey)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	serverCertPEM = append(serverCertPEM, caCertPEM...)
	fmt.Printf(showCertCmdFmt, string(serverCertPEM))
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	tlsCert, _ = tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	// create server
	tlsServerConfig := &tls.Config{
		Certificates:             []tls.Certificate{tlsCert},
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hi there")
	})
	server := &http.Server{
		Addr:         "localhost:2000",
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig:    tlsServerConfig,
		Handler:      mux,
	}

	// run the server
	go func() {
		_ = server.ListenAndServeTLS("", "")
	}()
	time.Sleep(100 * time.Millisecond)
	defer server.Close()

	// create client
	tlsClientConfig := &tls.Config{
		// ServerName:               "localhost",
		RootCAs:                  x509.NewCertPool(),
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	tlsClientConfig.RootCAs.AddCert(caCert)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
		Timeout: time.Duration(300 * time.Second),
	}

	// client request from the server
	res, err := client.Get("https://localhost:2000")
	if err != nil {
		fmt.Printf("Error GET-ing from the server:\n%+v", err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	fmt.Printf("Got from the server:\n%s", string(body))
	if err != nil {
		fmt.Printf("Error readiing the response:\n%+v", err)
		return
	}
}
