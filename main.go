package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"go.step.sm/crypto/pemutil"
	"golang.org/x/term"
)

// Default error handler, declared as a variable so it can be overridden
// in tests.
var die = func(err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	os.Exit(1)
}

// Generic wrapper for any function with error as its second return type,
// so the caller doesn't have to worry about error handling.
func must[T any](retval T, err error) T {
	if err != nil {
		die(err)
	}
	return retval
}

// Get password for key decryption, declared as a variable so it can be
// overridden in tests.
var getPassword = func() []byte {
	fmt.Fprintf(os.Stderr, "PEM password: ")
	password := must(term.ReadPassword(int(os.Stdin.Fd())))
	fmt.Fprintf(os.Stderr, "\n")
	return password
}

// Scan through the in-memory contents of a PEM file looking for a private
// key block, then extract it after decrypting it if necessary.
func extractKey(pemBytes []byte) ([]byte, error) {
	block, rest := pem.Decode(pemBytes)
	for block != nil {
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			password := getPassword()
			block = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: must(pemutil.DecryptPKCS8PrivateKey(block.Bytes, password)),
			}
		}
		if block.Type == "PRIVATE KEY" {
			return pem.EncodeToMemory(block), nil
		}
		block, rest = pem.Decode(rest)
	}
	return nil, fmt.Errorf("no private key found")
}

// Load a certificate/private key pair from the given PEM file.
func loadCert(filename string) tls.Certificate {
	pemFile := must(os.Open(filename))
	defer pemFile.Close()
	pemBytes := must(io.ReadAll(pemFile))
	cert := must(tls.X509KeyPair(pemBytes, must(extractKey(pemBytes))))
	cert.Leaf = must(x509.ParseCertificate(cert.Certificate[0]))
	return cert
}

// Return an HTTP client that skips server verification for ease of testing
// but presents the given client certificate when it connects.
func getClient(cert tls.Certificate) http.Client {
	return http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <PEM file> <url>\n", os.Args[0])
		os.Exit(1)
	}
	cert := loadCert(os.Args[1])
	url := os.Args[2]
	client := getClient(cert)
	resp := must(client.Get(url))
	defer resp.Body.Close()
	body := must(io.ReadAll(resp.Body))
	fmt.Fprintf(os.Stderr, "%s\n", resp.Status)
	fmt.Printf("%s\n", body)
}
