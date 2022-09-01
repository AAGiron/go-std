package liboqs_sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"io"
	"crypto/rand"
	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/cryptobyte"
)

// ID identifies each type of Hybrid Signature.
type ID uint16

const (
	P256_Dilithium2 ID = 0x21c
	P256_Falcon512 ID = 0x21d
	P256_RainbowIClassic ID = 0x21e
	
	P384_Dilithium3 ID = 0x21f
	P384_RainbowIIIClassic ID = 0x220
	
	P521_Dilithium5 ID = 0x221
	P521_Falcon1024 ID = 0x222
	P521_RainbowVClassic ID = 0x223

	Dilithium2 ID = 0x224
	Falcon512 ID = 0x225
	
	Dilithium3 ID = 0x226	
	
	Dilithium5 ID = 0x227
	Falcon1024 ID = 0x228
)

const (
	isHybrid uint8 = 1
	isPQCOnly uint8 = 2
)


// Hybrid Signature public key
type PublicKey struct {
	SigId ID
	classic *ecdsa.PublicKey 
	pqc []byte
}

// Hybrid Signature private key
type PrivateKey struct {
	SigId ID
	classic *ecdsa.PrivateKey	
	pqc []byte
	hybridPub *PublicKey
}


// Private Key methods
// Implementing the crypto.Signer interface

func (priv *PrivateKey) Public() crypto.PublicKey {
	return *priv.hybridPub
}


func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	var classicSig []byte

	if priv.classic != nil {
		classicSig, err = priv.classic.Sign(rand, digest, opts)
		if err != nil {
			return nil, err
		}
	}
	
	pqcSigner := oqs.Signature{}

	if err := pqcSigner.Init(sigIdtoName[priv.SigId], priv.pqc); err != nil {
		return nil, err
	}

	pqcSig, err := pqcSigner.Sign(digest)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	
	if priv.classic != nil {
		b.AddUint8(isHybrid)
		b.AddUint16(uint16(len(classicSig)))
		b.AddBytes(classicSig)
		b.AddUint16(uint16(len(pqcSig)))
		b.AddBytes(pqcSig)
	} else {
		b.AddUint8(isPQCOnly)
		b.AddUint16(uint16(len(pqcSig)))
		b.AddBytes(pqcSig)
	}	
	
	return b.BytesOrPanic(), nil
}

// Public Key methods

func (pub *PublicKey) MarshalBinary() ([]byte) {
	var b cryptobyte.Builder
	var classicPubBytes []byte

	if pub.classic != nil {
		classicPubBytes = elliptic.Marshal(pub.classic.Curve, pub.classic.X, pub.classic.Y)
		b.AddUint16(uint16(pub.SigId))
		b.AddBytes(classicPubBytes)  // Classic bytes
		b.AddBytes(pub.pqc)  // PQC bytes
	} else {
		b.AddUint16(uint16(pub.SigId))	
		b.AddBytes(pub.pqc)  // PQC bytes
	}
		
	return b.BytesOrPanic()
}

func (pub *PublicKey) UnmarshalBinary(raw []byte) error {

	pub.SigId = ID(binary.BigEndian.Uint16(raw[:2]))

	if IsSigHybrid(pub.SigId) {
		var classicPubSize int
		
		pub.classic = new(ecdsa.PublicKey)
		pub.classic.Curve, classicPubSize = ClassicFromSig(pub.SigId) 

		classicBytes := raw[2:2 + classicPubSize]
		pqcBytes := raw[2 + classicPubSize:]

		pub.classic.X, pub.classic.Y =	elliptic.Unmarshal(pub.classic.Curve, classicBytes)
		if pub.classic.X == nil {
			return errors.New("error in unmarshal ecdsa public key")
		}	
		
		pub.pqc = pqcBytes
	} else {
		pub.pqc = raw[2:]
	}
		
	return nil
}


func (pub *PublicKey) Verify(signed, sig []byte) (bool, error) {
	var current uint16
	var classicValid bool

	sigType := sig[0]

	current = 1
	if sigType == isHybrid {

		classicSize := binary.BigEndian.Uint16(sig[current:current+2])
		current = current + 2
		classicSig := sig[current:current + classicSize]

		current = current + classicSize

		classicValid = ecdsa.VerifyASN1(pub.classic, signed, classicSig)
	}
	
	pqcSize := binary.BigEndian.Uint16(sig[current:current + 2])
	
	current = current + 2
	
	pqcSig := sig[current:current + pqcSize]

	verifier := oqs.Signature{}

	if err := verifier.Init(sigIdtoName[pub.SigId], nil); err != nil {
		return false, err
	}

	pqcValid, err := verifier.Verify(signed, pqcSig, pub.pqc)
	if err != nil {
		return false, err
	}

	if sigType == isHybrid {
		if classicValid && pqcValid {
			return true, nil
		}
	}

	if pqcValid {
		return true, nil
	}

	return false, nil
}


// Package Functions

func GenerateKey(sigId ID) (*PublicKey, *PrivateKey, error) {
	pub := new(PublicKey)
	priv := new(PrivateKey)

	if IsSigHybrid(sigId) {
		curve, _ := ClassicFromSig(sigId)

		// Classic
		classicPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pub.classic = &classicPriv.PublicKey
		priv.classic = classicPriv
	} else {
		pub.classic = nil
		priv.classic = nil
	}
	
	// PQC

	oqsSignature := oqs.Signature{}

	if err := oqsSignature.Init(sigIdtoName[sigId], nil); err != nil {
		return nil, nil, err
	}

	pqcPub, err := oqsSignature.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pqcPriv := oqsSignature.ExportSecretKey()	

	pub.SigId = sigId
	pub.pqc = pqcPub

	priv.SigId = sigId	
	priv.pqc = pqcPriv
	priv.hybridPub = pub


	return pub, priv, nil
}

// This function is only called in our tests.
// Used in the unmarshalling of the hybrid root CA certificate and keys
func ConstructPublicKey(_sigID ID, _classic *ecdsa.PublicKey, _pqc []byte) *PublicKey {
	return &PublicKey{SigId: _sigID, classic: _classic, pqc: _pqc}
}

// This function is only called in our tests.
// Used in the unmarshalling of the hybrid root CA certificate and keys
func ConstructPrivateKey(_sigID ID, _classic *ecdsa.PrivateKey, _pqc []byte, _hybridPub *PublicKey) *PrivateKey {
	return &PrivateKey{SigId: _sigID, classic: _classic, pqc: _pqc, hybridPub: _hybridPub}
}

// This function is only called in our tests.
// Used in the marshalling of the hybrid root CA certificate and keys
func GetPrivateKeyMembers(priv *PrivateKey) (*ecdsa.PrivateKey, []byte, *PublicKey){
	return priv.classic, priv.pqc, priv.hybridPub
}

// This function is only called in our tests.
// Used in the marshalling of the hybrid root CA certificate and keys
func GetPublicKeyMembers(pub *PublicKey) (*ecdsa.PublicKey, []byte){
	return pub.classic, pub.pqc
}


// Returns classical curve and public key size for the corresponding curve
func ClassicFromSig(sigId ID) (elliptic.Curve, int) {
	switch true {
	case sigId >= P256_Dilithium2 && sigId <= P256_RainbowIClassic:
		return elliptic.P256(), 65
	case sigId >= P384_Dilithium3 && sigId <= P384_RainbowIIIClassic:
		return elliptic.P384(), 97
	case sigId >= P521_Dilithium5 && sigId <= P521_RainbowVClassic:
		return elliptic.P521(), 133
	default:
		return nil, 0
	}
}

func HashFromSig(sigId ID) (crypto.Hash, error) {
	switch true {
	case sigId >= P256_Dilithium2 && sigId <= P256_RainbowIClassic:
		return crypto.SHA256, nil
	case sigId >= P384_Dilithium3 && sigId <= P384_RainbowIIIClassic:
		return crypto.SHA384, nil
	case sigId >= P521_Dilithium5 && sigId <= P521_RainbowVClassic:
		return crypto.SHA512, nil
	default:
		return crypto.SHA256, errors.New("unknown signature ID")
	}
}

func IsSigHybrid(sigID ID) bool {
	if sigID >= P256_Dilithium2 && sigID <= P521_RainbowVClassic {
		return true
	}
	return false
}

var sigIdtoName = map[ID]string {
	P256_Dilithium2: "Dilithium2", P256_Falcon512: "Falcon-512", P256_RainbowIClassic: "Rainbow-I-Classic", 
	P384_Dilithium3: "Dilithium3", P384_RainbowIIIClassic: "Rainbow-III-Classic", 
	P521_Dilithium5: "Dilithium5", P521_Falcon1024: "Falcon-1024", P521_RainbowVClassic: "Rainbow-V-Classic",
	Dilithium2: "Dilithium2", Falcon512: "Falcon-512",
	Dilithium3: "Dilithium3",
	Dilithium5: "Dilithium5", Falcon1024: "Falcon-1024",
}