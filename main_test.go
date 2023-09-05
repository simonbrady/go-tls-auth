package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const want = "CN=gopher"
const addr = "127.0.0.1:12345"

func dummyPassword() []byte {
	return []byte("password")
}

func TestLoadCertificate(t *testing.T) {
	getPassword = dummyPassword
	for _, filename := range []string{
		"testdata/certfirst.pem",
		"testdata/certfirst_decrypted.pem",
		"testdata/keyfirst.pem",
		"testdata/keyfirst_decrypted.pem",
	} {
		die = func(err error) {
			t.Fatalf("failed on %s: %v", filename, err)
		}
		cert := loadCert(filename)
		got := cert.Leaf.Subject.String()
		if got != want {
			t.Errorf("failed on %s: got subject %q, want %q", filename, got, want)
		}
	}
}

type handler struct {
	Shutdown context.CancelFunc
	Test     *testing.T
}

func (h handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer h.Shutdown()
	t := h.Test
	certs := len(req.TLS.PeerCertificates)
	if certs != 1 {
		t.Errorf("got %d client certificates, expected 1", certs)
		return
	}
	got := req.TLS.PeerCertificates[0].Subject.String()
	if got != want {
		t.Errorf("got subject %q, want %q", got, want)
		return
	}
}

func startServer(server *http.Server, t *testing.T) {
	if err := server.ListenAndServeTLS("testdata/test.crt", "testdata/decrypted.key"); err != http.ErrServerClosed {
		t.Error(err)
	}
}

func TestClient(t *testing.T) {
	die = func(err error) {
		t.Fatal(err)
	}
	getPassword = dummyPassword
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := &http.Server{
		Addr: addr,
		Handler: handler{
			Shutdown: cancel,
			Test:     t,
		},
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
		},
	}
	go startServer(server, t)
	cert := loadCert("testdata/certfirst.pem")
	client := getClient(cert)
	if resp, err := client.Get(fmt.Sprintf("https://%s", addr)); err != nil {
		t.Error(err)
	} else {
		defer resp.Body.Close()
	}
	<-ctx.Done()
	if ctx.Err() != context.Canceled {
		t.Errorf("no request received from client")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Error(err)
	}
}
