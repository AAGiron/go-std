package keystore

import (
	"os"
	"time"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func StoreTrustedCertificate(keystoreFilePath, keystorePassword, alias string, certificate []byte) error {	

	// Creating Keystore
	ks := keystore.New()	

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

func ReadKeyStore(filename string, password []byte) (keystore.KeyStore, error) {
	f, err := os.Open(filename)
	if err != nil {
		return keystore.KeyStore{}, err
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