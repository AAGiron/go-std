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
)


// Hybrid Signature public key
type HybridPublicKey struct {
	SigId ID
	classic *ecdsa.PublicKey 
	pqc []byte
}

// Hybrid Signature private key
type HybridPrivateKey struct {
	SigId ID
	classic *ecdsa.PrivateKey	
	pqc []byte
	hybridPub *HybridPublicKey
}


// Private Key methods
// Implementing the crypto.Signer interface

func (priv *HybridPrivateKey) Public() crypto.PublicKey {
	return *priv.hybridPub
}


func (priv *HybridPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	classicSig, err := priv.classic.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
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
	
	b.AddUint16(uint16(len(classicSig)))
	b.AddBytes(classicSig)
	b.AddUint16(uint16(len(pqcSig)))
	b.AddBytes(pqcSig)


	return b.BytesOrPanic(), nil
}

// Public Key methods

func (pub *HybridPublicKey) MarshalBinary() ([]byte) {
	var b cryptobyte.Builder
	
	classicPubBytes := elliptic.Marshal(pub.classic.Curve, pub.classic.X, pub.classic.Y)
		
	b.AddUint16(uint16(pub.SigId))
	b.AddBytes(classicPubBytes)  // Classic bytes
	b.AddBytes(pub.pqc)  // PQC bytes

	return b.BytesOrPanic()
}

func (pub *HybridPublicKey) UnmarshalBinary(raw []byte) error {

	var classicPubSize int
	
	pub.SigId = ID(binary.BigEndian.Uint16(raw[:2]))
	
	pub.classic = new(ecdsa.PublicKey)
	pub.classic.Curve, classicPubSize = ClassicFromSig(pub.SigId) 

	classicBytes := raw[2:2 + classicPubSize]
	pqcBytes := raw[2 + classicPubSize:]

	pub.classic.X, pub.classic.Y =	elliptic.Unmarshal(pub.classic.Curve, classicBytes)
	if pub.classic.X == nil {
		return errors.New("error in unmarshal ecdsa public key")
	}	
	
	pub.pqc = pqcBytes

	return nil
}


func (pub *HybridPublicKey) Verify(signed, sig []byte) (bool, error) {

	classicSize := binary.BigEndian.Uint16(sig[:2])		
	classicSig := sig[2:2 + classicSize]	

	current := 2 + classicSize

	pqcSize := binary.BigEndian.Uint16(sig[current:current + 2])
	
	current = current + 2
	
	pqcSig := sig[current:current + pqcSize]

	classicValid := ecdsa.VerifyASN1(pub.classic, signed, classicSig)

	verifier := oqs.Signature{}

	if err := verifier.Init(sigIdtoName[pub.SigId], nil); err != nil {
		return false, err
	}

	pqcValid, err := verifier.Verify(signed, pqcSig, pub.pqc)
	if err != nil {
		return false, err
	}

	if classicValid && pqcValid {
		return true, nil
	}

	return false, nil
}


// Package Functions

func GenerateKey(sigId ID) (*HybridPublicKey, *HybridPrivateKey, error) {

	curve, _ := ClassicFromSig(sigId)

	// Classic
	classicPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	classicPub := &classicPriv.PublicKey

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

	// Hybrid Keypair

	pub := new(HybridPublicKey)
	priv := new(HybridPrivateKey)

	pub.SigId = sigId
	pub.classic = classicPub
	pub.pqc = pqcPub

	priv.SigId = sigId
	priv.classic = classicPriv
	priv.pqc = pqcPriv
	priv.hybridPub = pub


	return pub, priv, nil
}

// This function is only called in our tests.
// Used in the unmarshalling of the hybrid root CA certificate and keys
func ConstructPublicKey(_sigID ID, _classic *ecdsa.PublicKey, _pqc []byte) *HybridPublicKey {
	return &HybridPublicKey{SigId: _sigID, classic: _classic, pqc: _pqc}
}

// This function is only called in our tests.
// Used in the unmarshalling of the hybrid root CA certificate and keys
func ConstructPrivateKey(_sigID ID, _classic *ecdsa.PrivateKey, _pqc []byte, _hybridPub *HybridPublicKey) *HybridPrivateKey {
	return &HybridPrivateKey{SigId: _sigID, classic: _classic, pqc: _pqc, hybridPub: _hybridPub}
}

// This function is only called in our tests.
// Used in the marshalling of the hybrid root CA certificate and keys
func GetPrivateKeyMembers(priv *HybridPrivateKey) (*ecdsa.PrivateKey, []byte, *HybridPublicKey){
	return priv.classic, priv.pqc, priv.hybridPub
}

// This function is only called in our tests.
// Used in the marshalling of the hybrid root CA certificate and keys
func GetPublicKeyMembers(pub *HybridPublicKey) (*ecdsa.PublicKey, []byte){
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

var sigIdtoName = map[ID]string {
	P256_Dilithium2: "Dilithium2", P256_Falcon512: "Falcon-512", P256_RainbowIClassic: "Rainbow-I-Classic", 
	P384_Dilithium3: "Dilithium3", P384_RainbowIIIClassic: "Rainbow-III-Classic", 
	P521_Dilithium5: "Dilithium5", P521_Falcon1024: "Falcon-1024", P521_RainbowVClassic: "Rainbow-V-Classic",
}