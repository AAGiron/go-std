package kem

import (
	"circl/dh/sidh"
	"circl/kem/schemes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// ID identifies each type of KEM.
type ID uint16

const (
	// KEM25519 is X25519 as a KEM. Not quantum-safe.
	KEM25519 ID = 0x01fb
	// Kyber512 is a post-quantum KEM, as defined in: https://pq-crystals.org/kyber/ .
	Kyber512 ID = 0x01fc
	// SIKEp434 is a post-quantum KEM, as defined in: https://sike.org/ .
	SIKEp434 ID = 0x01fd
	// Liboqs Hybrids
	P256_Kyber512  ID = 0x0204
	P384_Kyber768  ID = 0x0205
	P521_Kyber1024 ID = 0x0206

	P256_LightSaber_KEM ID = 0x0207
	P384_Saber_KEM      ID = 0x0208
	P521_FireSaber_KEM  ID = 0x0209

	P256_NTRU_HPS_2048_509 ID = 0x020a
	P384_NTRU_HPS_2048_677 ID = 0x020b
	P521_NTRU_HPS_4096_821 ID = 0x020c

	P521_NTRU_HPS_4096_1229 ID = 0x020d

	P384_NTRU_HRSS_701  ID = 0x020e
	P521_NTRU_HRSS_1373 ID = 0x020f

	// Liboqs PQC
	OQS_Kyber512  ID = 0x0210
	OQS_Kyber768  ID = 0x0211
	OQS_Kyber1024 ID = 0x0212

	LightSaber_KEM ID = 0x0213
	Saber_KEM      ID = 0x0214
	FireSaber_KEM  ID = 0x0215

	NTRU_HPS_2048_509 ID = 0x0216
	NTRU_HPS_2048_677 ID = 0x0217
	NTRU_HPS_4096_821 ID = 0x0218

	NTRU_HPS_4096_1229 ID = 0x0219

	NTRU_HRSS_701  ID = 0x021a
	NTRU_HRSS_1373 ID = 0x021b

	P256_Classic_McEliece_348864 ID = 0x021c
)

// PrivateKey is a KEM private key.
type PrivateKey struct {
	KEMId      ID
	PrivateKey []byte
}

// PublicKey is a KEM public key.
type PublicKey struct {
	KEMId     ID
	PublicKey []byte
}

// MarshalBinary returns the byte representation of a KEM public key.
func (pubKey *PublicKey) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder

	b.AddUint16(uint16(pubKey.KEMId))
	b.AddBytes(pubKey.PublicKey)

	return b.BytesOrPanic(), nil
}

// UnmarshalBinary produces a PublicKey from a byte array.
func (pubKey *PublicKey) UnmarshalBinary(raw []byte) error {
	s := cryptobyte.String(raw)

	var id uint16
	if !s.ReadUint16(&id) {
		return errors.New("crypto/kem: invalid algorithm")
	}

	kemID := ID(id)
	pubKey.KEMId = kemID
	pubKey.PublicKey = raw[2:]
	return nil
}

// GenerateKey generates a keypair for a given KEM.
// It returns a KEM public and private key.
func GenerateKey(rand io.Reader, kemID ID) (*PublicKey, *PrivateKey, error) {
	switch kemID {
	case Kyber512:
		scheme := schemes.ByName("Kyber512")
		seed := make([]byte, scheme.SeedSize())
		if _, err := io.ReadFull(rand, seed); err != nil {
			return nil, nil, err
		}
		publicKey, privateKey := scheme.DeriveKeyPair(seed)
		pk, _ := publicKey.MarshalBinary()
		sk, _ := privateKey.MarshalBinary()

		return &PublicKey{KEMId: kemID, PublicKey: pk}, &PrivateKey{KEMId: kemID, PrivateKey: sk}, nil
	case KEM25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}
		return &PublicKey{KEMId: kemID, PublicKey: publicKey}, &PrivateKey{KEMId: kemID, PrivateKey: privateKey}, nil
	case SIKEp434:
		privateKey := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		publicKey := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		if err := privateKey.Generate(rand); err != nil {
			return nil, nil, err
		}
		privateKey.GeneratePublicKey(publicKey)

		pubBytes := make([]byte, publicKey.Size())
		privBytes := make([]byte, privateKey.Size())
		publicKey.Export(pubBytes)
		privateKey.Export(privBytes)
		return &PublicKey{KEMId: kemID, PublicKey: pubBytes}, &PrivateKey{KEMId: kemID, PrivateKey: privBytes}, nil
	case IsLiboqs(kemID):

		var pubBytes, privBytes []byte
		var err error

		if isPQCLiboqs(kemID) {
			oqsKEM := oqs.KeyEncapsulation{}

			if err := oqsKEM.Init(liboqsPQCKEMString[kemID], nil); err != nil {
				return nil, nil, err
			}
			pubBytes, err = oqsKEM.GenerateKeyPair()
			if err != nil {
				return nil, nil, err
			}
			privBytes = oqsKEM.ExportSecretKey()
		} else {
			scheme := liboqsSchemeMap[kemID]

			pubBytes, privBytes, err = scheme.Keygen()
			if err != nil {
				return nil, nil, err
			}
		}
		return &PublicKey{KEMId: kemID, PublicKey: pubBytes}, &PrivateKey{KEMId: kemID, PrivateKey: privBytes}, nil

	default:
		return nil, nil, fmt.Errorf("crypto/kem: internal error: unsupported KEM %d", kemID)
	}
}

// Encapsulate returns a shared secret and a ciphertext.
func Encapsulate(rand io.Reader, pk *PublicKey) (sharedSecret []byte, ciphertext []byte, err error) {
	switch pk.KEMId {
	case Kyber512:
		scheme := schemes.ByName("Kyber512")
		pub, err := scheme.UnmarshalBinaryPublicKey(pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		seed := make([]byte, scheme.EncapsulationSeedSize())
		if _, err := io.ReadFull(rand, seed); err != nil {
			return nil, nil, err
		}

		ct, ss, err := scheme.EncapsulateDeterministically(pub, seed)
		if err != nil {
			return nil, nil, err
		}
		return ss, ct, nil
	case KEM25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, nil, err
		}
		ciphertext, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, err := curve25519.X25519(privateKey, pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return sharedSecret, ciphertext, nil
	case SIKEp434:
		kem := sidh.NewSike434(rand)
		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		err := sikepk.Import(pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		ct := make([]byte, kem.CiphertextSize())
		ss := make([]byte, kem.SharedSecretSize())
		err = kem.Encapsulate(ct, ss, sikepk)
		if err != nil {
			return nil, nil, err
		}
		return ss, ct, nil
	case IsLiboqs(pk.KEMId):

		var ss, ct []byte
		var err error

		if isPQCLiboqs(pk.KEMId) {
			oqsKEM := oqs.KeyEncapsulation{}

			if err := oqsKEM.Init(liboqsPQCKEMString[pk.KEMId], nil); err != nil {
				return nil, nil, err
			}

			ct, ss, err = oqsKEM.EncapSecret(pk.PublicKey)
			if err != nil {
				return nil, nil, err
			}

		} else {
			scheme := liboqsSchemeMap[pk.KEMId]

			ct, ss, err = scheme.Encapsulate(pk)
			if err != nil {
				return nil, nil, err
			}
		}

		return ss, ct, nil
	default:
		return nil, nil, errors.New("crypto/kem: internal error: unsupported KEM in Encapsulate")
	}
}

// Decapsulate returns the shared secret given the private key and the ciphertext.
func Decapsulate(privateKey *PrivateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	switch privateKey.KEMId {
	case Kyber512:
		scheme := schemes.ByName("Kyber512")
		sk, err := scheme.UnmarshalBinaryPrivateKey(privateKey.PrivateKey)
		if err != nil {
			return nil, err
		}
		if len(ciphertext) != scheme.CiphertextSize() {
			return nil, fmt.Errorf("crypto/kem: ciphertext is of len %d, expected %d", len(ciphertext), scheme.CiphertextSize())
		}
		ss, err := scheme.Decapsulate(sk, ciphertext)
		if err != nil {
			return nil, err
		}
		return ss, nil
	case KEM25519:
		sharedSecret, err := curve25519.X25519(privateKey.PrivateKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	case SIKEp434:
		kem := sidh.NewSike434(nil)
		sikesk := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		err := sikesk.Import(privateKey.PrivateKey)
		if err != nil {
			return nil, err
		}

		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		sikesk.GeneratePublicKey(sikepk)
		ss := make([]byte, kem.SharedSecretSize())
		err = kem.Decapsulate(ss, sikesk, sikepk, ciphertext)
		if err != nil {
			return nil, err
		}

		return ss, nil
	case IsLiboqs(privateKey.KEMId):
		var ss []byte
		var err error

		if isPQCLiboqs(privateKey.KEMId) {
			oqsKEM := oqs.KeyEncapsulation{}

			if err := oqsKEM.Init(liboqsPQCKEMString[privateKey.KEMId], privateKey.PrivateKey); err != nil {
				return nil, err
			}

			ss, err = oqsKEM.DecapSecret(ciphertext)
			if err != nil {
				return nil, err
			}

		} else {
			scheme := liboqsSchemeMap[privateKey.KEMId]

			ss, err = scheme.Decapsulate(privateKey, ciphertext)
			if err != nil {
				return nil, err
			}
		}

		return ss, nil
	default:
		return nil, errors.New("crypto/kem: internal error: unsupported KEM in Decapsulate")
	}
}

func SchemeFromID(id ID) string {
	return liboqsPQCKEMString[id]
}