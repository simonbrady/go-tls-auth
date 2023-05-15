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

func die(err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	os.Exit(1)
}

func must[T any](retval T, err error) T {
	if err != nil {
		die(err)
	}
	return retval
}

func getKey(pemBytes []byte) ([]byte, error) {
	block, rest := pem.Decode(pemBytes)
	for block != nil {
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			fmt.Fprintf(os.Stderr, "Password: ")
			password := must(term.ReadPassword(int(os.Stdin.Fd())))
			fmt.Fprintf(os.Stderr, "\n")
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

func getCert(filename string) tls.Certificate {
	pemFile := must(os.Open(filename))
	defer pemFile.Close()
	pemBytes := must(io.ReadAll(pemFile))
	cert := must(tls.X509KeyPair(pemBytes, must(getKey(pemBytes))))
	cert.Leaf = must(x509.ParseCertificate(cert.Certificate[0]))
	return cert
}

func getClient(cert tls.Certificate) http.Client {
	return http.Client{
		Transport: &http.Transport{
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
	cert := getCert(os.Args[1])
	url := os.Args[2]
	client := getClient(cert)
	resp := must(client.Get(url))
	body := must(io.ReadAll(resp.Body))
	fmt.Fprintf(os.Stderr, "%s\n", resp.Status)
	fmt.Printf("%s\n", body)
}
