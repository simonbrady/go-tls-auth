package main

import "testing"

func TestLoadCertificate(t *testing.T) {
	const want = "CN=gopher"
	getPassword = func() []byte {
		return []byte("password")
	}
	for _, filename := range []string{
		"testdata/certfirst.pem",
		"testdata/certfirst_decrypted.pem",
		"testdata/keyfirst.pem",
		"testdata/keyfirst_decrypted.pem",
	} {
		cert := loadCert(filename)
		got := cert.Leaf.Subject.String()
		if got != want {
			t.Errorf("failed on %s: got subject %q, want %q", filename, got, want)
		}
	}
}
