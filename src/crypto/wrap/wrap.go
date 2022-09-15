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

type PublicKey struct {
	ClassicAlgorithm  elliptic.Curve
	WrappedPk []byte
}

func WrapPublicKey(plaintext, key []byte) (ciphertext []byte, err error) {

	if len(key) != 32 {
		return nil, errors.New("wrapped cert: key should be 32 bytes long")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertextPk := aesgcm.Seal(nil, nonce, plaintext, nil)	

	var b cryptobyte.Builder	
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {		
		b.AddBytes(ciphertextPk)			
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(nonce)
	})      

	fmt.Printf("Wrapping a Public Key:\nOriginal public key: %x\nWrapped public key: %x\n\nWrapped with:\nCert PSK: %x\nNonce: %x\n\n", plaintext[:10], ciphertextPk[:10], key[:10], nonce[:10])

	return b.BytesOrPanic(), nil
}

func UnwrapPublicKey(ciphertext, key []byte) (plaintext []byte, err error) {

	var wrappedPk, nonce []byte

	s := cryptobyte.String(ciphertext)
	if !readUint8LengthPrefixed(&s, &wrappedPk) ||
		 !readUint8LengthPrefixed(&s, &nonce) ||
		 !s.Empty() {
		return nil, errors.New("could not unwrap public key")
	}

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

	fmt.Printf("Unwrapping a public key:\nWrapped public key %x\nUnwrapped public key: %x\n\nUnwrapped with:\nCert PSK: %x\nNonce: %x\n\n", wrappedPk[:10], plaintext[:10], key[:10], nonce[:10])

	return plaintext, nil
}


// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}
