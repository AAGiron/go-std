package wrap

/*
#cgo CFLAGS: -g -Wall
#cgo LDFLAGS: -L. -lcrypto_aead_ascon80pqv12_ref
#include <stdlib.h>
#include "ascon80pq.h"
*/
import "C"
import (
	"crypto/rand"
	"fmt"
	"io"
	"unsafe"
)

const (
	CRYPTO_KEYBYTES = 20
	CRYPTO_NPUBBYTES = 16
	CRYPTO_ABYTES = 16
)

func ascon80pqEncrypt(plaintext, key []byte) (goCiphertextBytes []byte, nonce []byte, err error) {
	if len(key) != CRYPTO_KEYBYTES {
		panic("incorrect key size for Ascon80pq.")
	}
	
	// AEAD's Associated Data
	associatedData := [16]byte{0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15}

	nonce = make([]byte, CRYPTO_NPUBBYTES)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	ciphertextBytes := C.malloc(C.sizeof_char * C.ulong(len(plaintext) + CRYPTO_ABYTES))

	ciphertextLen := C.ulonglong(0)
	plaintextLen := C.ulonglong(len(plaintext))
	alen := C.ulonglong(len(associatedData))  	  		
	zerobyte := C.uchar(0)
  	
	// Converting Go []bytes to C pointers
	plaintextBytes := (*C.uchar)(C.CBytes(plaintext[:]))
	adBytes := (*C.uchar)(C.CBytes(associatedData[:]))
	nonceBytes := (*C.uchar)(C.CBytes(nonce[:]))
	keyBytes := (*C.uchar)(C.CBytes(key[:]))	
	
  //Encrypt
	ret := C.crypto_aead_encrypt((*C.uchar)(ciphertextBytes), &ciphertextLen, 
															 plaintextBytes, plaintextLen, 
															 adBytes, alen, 
															 &(zerobyte), nonceBytes, 
															 keyBytes)

	if ret != 0 {
		return nil, nil, fmt.Errorf("ascon80pq encryption failed with error code %d", ret)
	}

	goCiphertextBytes = C.GoBytes(unsafe.Pointer(ciphertextBytes), C.int(ciphertextLen))

	return goCiphertextBytes, nonce, nil
}

func ascon80pqDecrypt(ciphertext, nonce, key []byte) ([]byte, error) {

		// AEAD's Associated Data
		associatedData := [16]byte{0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15}		
		
		ciphertextLen := C.ulonglong(len(ciphertext))		
		plaintextLen := C.ulonglong(len(ciphertext) - CRYPTO_ABYTES)		
		alen := C.ulonglong(len(associatedData))
		zerobyte := C.uchar(0)

		ciphertextBytes := (*C.uchar)(C.CBytes(ciphertext[:]))
		adBytes := (*C.uchar)(C.CBytes(associatedData[:]))
		nonceBytes := (*C.uchar)(C.CBytes(nonce[:]))
		keyBytes := (*C.uchar)(C.CBytes(key[:]))

		ptr := C.malloc(C.sizeof_char * C.ulong(plaintextLen))
		defer C.free(unsafe.Pointer(ptr))
		
		ret := C.crypto_aead_decrypt((*C.uchar)(ptr), &plaintextLen, &(zerobyte), ciphertextBytes, 
		ciphertextLen, adBytes, alen, nonceBytes, keyBytes);

		decryptedPlaintext := C.GoBytes(ptr, C.int(plaintextLen))		

		if ret != 0 {
			return nil, fmt.Errorf("ascon80pq decryption failed with error code %d", ret)
		}

		return decryptedPlaintext, nil
}