
// Package wrap implements functions and structs to wrap/unwrap public keys according to PKIELP proposal
// and implements in interface to Ascon-80pq encrypt and decrypt operations.
package wrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// PublicKey contains the wrapped public key and information related to it.
type PublicKey struct {

	// ClassicAlgorithm is the ECDSA curve of the public key, before being wrapped.
	ClassicAlgorithm  elliptic.Curve

	// WrapAlgorithm is the name of the symmetric encryption algorithm used to encrypt/wrap the public key.
	WrapAlgorithm string

	// WrappedPk is the wrapped public key bytes.
	WrappedPk []byte
}

// GetNameString returns the wrapped algorithm name, which is composed by the
// symmetric encryption algorithm name plus the original public key's algorithm name (a classic algorithm).
// Example: AES256_ECDSA-P256.
func (pub *PublicKey) GetNameString() string {
	var classicEC string
	
	switch pub.ClassicAlgorithm {
	case elliptic.P256():
		classicEC = "P256"
	case elliptic.P384():
		classicEC = "P384"
	case elliptic.P521():
		classicEC = "P521"
	default:
		classicEC = "Unknown"
	}

	return pub.WrapAlgorithm + "_ECDSA-" + classicEC
}

// WrapPublicKey encrypts `plaintext` which is expected to be a public key with `key` using `wrapAlgorithm`,
// returning a wrapped public key.
func WrapPublicKey(plaintext, key []byte, wrapAlgorithm string) (ciphertext []byte, err error) {
	var ciphertextPk []byte	
	var nonce []byte

	if wrapAlgorithm == "AES256" {
		if len(key) != 32 {
			return nil, errors.New("wrapped cert: key should be 32 bytes long")
		}
	
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}		
	
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonce = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	
		ciphertextPk = aesgcm.Seal(nil, nonce, plaintext, nil)	
	} else if wrapAlgorithm == "Ascon80pq" {
		var err error
		
		ciphertextPk, nonce, err = ascon80pqEncrypt(plaintext, key)
		if err != nil {
			return nil, err
		}		
	} else {
		return nil, errors.New("unknown wrap algorithm")
	}
	
	var b cryptobyte.Builder	
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {		
		b.AddBytes(ciphertextPk)			
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(nonce)
	})      

	wrappedPk := b.BytesOrPanic()

	fmt.Printf("Wrapping a Public Key (only the 10 first bytes are printed):\nOriginal public key: %x...\nWrapped public key: %x...\n\nWrapped with:\nCert PSK: %x...\nNonce: %x...\n\n", plaintext[:10], wrappedPk[:10], key[:10], nonce[:10])

	return wrappedPk, nil
}

// UnwrapPublicKey unwraps a wrapped public key, i.e. it decrypts `ciphertext` (which is expected to be a
// wrapped public key) using `key` and wrapAlgorithm.
func UnwrapPublicKey(ciphertext, key []byte, wrapAlgorithm string) (plaintext []byte, err error) {

	var wrappedPk, nonce []byte

	s := cryptobyte.String(ciphertext)
	if !readUint8LengthPrefixed(&s, &wrappedPk) ||
		 !readUint8LengthPrefixed(&s, &nonce) ||
		 !s.Empty() {
		return nil, errors.New("could not unwrap public key")
	}

	if wrapAlgorithm == "AES256" {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		plaintext, err = aesgcm.Open(nil, nonce, wrappedPk, nil)
		if err != nil {
			return nil, err
		}		
	} else if wrapAlgorithm == "Ascon80pq" {
		plaintext, err = ascon80pqDecrypt(wrappedPk, nonce, key)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("unknown wrap algorithm")
	}

	fmt.Printf("Unwrapping a public key (only the 10 first bytes are printed):\nWrapped public key %x...\nUnwrapped public key: %x...\n\nUnwrapped with:\nCert PSK: %x...\nNonce: %x...\n\n", wrappedPk[:10], plaintext[:10], key[:10], nonce[:10])

	return plaintext, nil
}


// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}
