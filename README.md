# TLS Client Authentication in Go

Demonstrates certificate-based TLS client authentication in Go.

Requires a PEM file containing an X.509 certificate and corresponding
private key in [PKCS#8](https://en.wikipedia.org/wiki/PKCS_8) format,
which can optionally be encrypted.

To create the PEM file with a self-signed cert and encrypted private key:

```
openssl req -x509 -newkey rsa:4096 -keyout /dev/stdout -out /dev/stdout -sha256 -days 365 -subj "/CN=gopher" > cert.pem
```

To leave the private key unencrypted (not recommended!), add `-nodes`
to the `openssl` command line.

Because of [this issue](https://github.com/golang/go/issues/8860) we
can't use the Go standard library for the decryption, so we use
[pemutil](https://pkg.go.dev/go.step.sm/crypto/pemutil) instead.
