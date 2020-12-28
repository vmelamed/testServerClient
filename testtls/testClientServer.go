package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

type testHandler struct {
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, "Hi there")
}

func testClientServer(tlsSrvCert *tls.Certificate, caCert *x509.Certificate) error {
	// create server
	tlsServerConfig := &tls.Config{
		Certificates:             []tls.Certificate{*tlsSrvCert},
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

	handler := &testHandler{}
	server := &http.Server{
		Addr:         "localhost:2000",
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig:    tlsServerConfig,
		Handler:      handler,
	}

	// run the server
	go func() {
		_ = server.ListenAndServeTLS("", "")
	}()
	time.Sleep(100 * time.Millisecond)
	defer server.Close()

	// create client
	tlsClientConfig := &tls.Config{
		ServerName:               "localhost",
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
		err = errors.Wrap(err, "error in client requesting from the server")
		return err
	}
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		err = errors.Wrap(err, "error reading the server response")
		return err
	}

	return nil
}
