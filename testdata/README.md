# Test Files

Files used for testing, generated as follows:

```
# Password = "password"
openssl req -x509 -newkey rsa:4096 -keyout test.key -out test.crt -sha256 -days 365 -subj "/CN=gopher"
openssl pkcs8 -in test.key -out decrypted.key
cat test.crt test.key > certfirst.pem
cat test.crt decrypted.key > certfirst_decrypted.pem
cat test.key test.crt > keyfirst.pem
cat decrypted.key test.crt > keyfirst_decrypted.pem
```
