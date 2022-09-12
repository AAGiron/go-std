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

	fmt.Printf("Wrap: Wrapped Pk: %x\n", ciphertextPk[:10])
	fmt.Printf("Wrap: Nonce: %x\n", nonce[:10])

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
	
	fmt.Printf("Unwrap: Ciphertext: %x\n", ciphertext[:10])
	fmt.Printf("Unwrap: Wrapped Pk: %x\n", wrappedPk[:10])
	fmt.Printf("Unwrap: Nonce: %x\n", nonce[:10])

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

	return plaintext, nil
}


// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}
