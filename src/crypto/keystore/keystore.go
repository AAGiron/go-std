
// Package keystore implements keystore/truststore operations.
package keystore

import (
	"errors"
	"os"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

var FailedToOpen error = errors.New("failed to open keystore file")

// StoreTrustedCertificate stores `certificate` in the truststore pointed by `keystoreFilePath`. Certificates
// stored in a truststore are trusted by the client, thus they are used to validate certificate chains.
func StoreTrustedCertificate(keystoreFilePath, keystorePassword, alias string, certificate []byte) error {	
	var ks keystore.KeyStore
	ks, err := ReadKeyStore(keystoreFilePath, []byte(keystorePassword))
	if errors.Is(err, FailedToOpen) {
		ks = keystore.New()	
	}

	trustedCertEntry := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type: "X509",
			Content: certificate,
		},
	}

	ks.SetTrustedCertificateEntry(alias, trustedCertEntry)

	return writeKeyStore(ks, keystoreFilePath, []byte(keystorePassword))
}

// writeKeyStore writes `ks` to the password-protected file `filename`.
func writeKeyStore(ks keystore.KeyStore, filename string, password []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer func() error {
		if err := f.Close(); err != nil {
			return err
		}
		return nil
	}()

	err = ks.Store(f, password)
	if err != nil {
		return err
	}

	return nil
}

// ReadKeyStore loads the keystore in `filename` with `password` and return it's content in a keystore.Keystore struct.
func ReadKeyStore(filename string, password []byte) (keystore.KeyStore, error) {
	f, err := os.Open(filename)
	if err != nil {
		return keystore.KeyStore{}, FailedToOpen
	}

	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		return keystore.KeyStore{}, err
	}

	return ks, nil
}
