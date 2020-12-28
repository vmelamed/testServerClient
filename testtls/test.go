package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func main() {
	var err error

	algo := "X25519"
	if len(os.Args) > 1 {
		algo = strings.ToUpper(os.Args[1])
	}

	useGenerated := false
	if len(os.Args) > 2 {
		useGenerated = strings.ToUpper(os.Args[2][:1]) == "G"
	}

	err = os.Mkdir("certs", os.ModeDir|os.FileMode(0755))
	if !os.IsExist(err) {
		fmt.Printf("Error creating the \"certs\" directory: %+v\n", err)
		os.Exit(1)
	}

	fmt.Println("TEST WITH FILE CERTIFICATES")
	serverCert := "certs/server-cert.pem"
	serverKey := "certs/server-key.pem"
	caCert := "certs/ca-cert.pem"
	if useGenerated {
		serverCert = "certs/server-cert-g.pem"
		serverKey = "certs/server-key-g.pem"
		caCert = "certs/ca-cert-g.pem"
	}
	tlsSrvCert1, caCert1, err := readCerts(serverCert, serverKey, caCert)
	if err != nil {
		err = errors.Wrap(err, "error reading certificates")
		fmt.Printf("Error reading certificates from files: %+v\n", err)
		os.Exit(1)
	}

	err = testClientServer(tlsSrvCert1, caCert1)
	if err == nil {
		fmt.Print("Success in Client-Server test with certificates from files\n")
	} else {
		fmt.Printf("Error in Client-Server test with certificates from files: %+v\n", err)
	}

	fmt.Println("TEST WITH GENERATED CERTIFICATES")
	tlsSrvCert2, caCert2, err := generateCerts(algo)
	if err != nil {
		err = errors.Wrap(err, "error generating certificates")
		fmt.Printf("Error generating the certificates: %+v\n", err)
		os.Exit(1)
	}

	err = testClientServer(tlsSrvCert2, caCert2)
	if err != nil {
		fmt.Printf("Error in Client-Server test with generated certificates: %+v\n", err)
		os.Exit(1)
	}

	fmt.Print("Success in Client-Server test with generated certificates\n")
}
