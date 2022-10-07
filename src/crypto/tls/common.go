// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/kem"
	"crypto/liboqs_sig"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"internal/cpu"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"golang.org/x/crypto/cryptobyte"
)

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

const (
	maxPlaintext       = 16384        // maximum plaintext payload length
	maxCiphertext      = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13 = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen    = 5            // record header length
	maxHandshake       = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords  = 16           // maximum number of consecutive non-advancing records
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeCertificateCachedInfo uint8 = 17  // Unassigned number. https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7	
	typeNewCertPSK					uint8 = 19  // Unassigned number. https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7	
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionCachedInfo              uint16 = 25
	extensionDelegatedCredentials    uint16 = 34
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionECH                     uint16 = 0xfe0a // draft-ietf-tls-esni-10
	extensionECHIsInner              uint16 = 0xda09 // draft-ietf-tls-esni-10
	extensionECHOuterExtensions      uint16 = 0xfd00 // draft-ietf-tls-esni-10
	extensionPDKKEMTLS               uint16 = 0xfd01 // arbitraly chosen
	extensionCertPSK                 uint16 = 0xfd02 // arbitraly chosen
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.3, this type is called NamedGroup, but at this time this library
// only supports Elliptic Curve based groups. See RFC 8446, Section 4.2.7.
type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
	X25519    CurveID = 29
	SIKEp434  CurveID = CurveID(kem.SIKEp434)
	Kyber512  CurveID = CurveID(kem.Kyber512)
	// Liboqs Hybrids
	P256_Kyber512  CurveID = CurveID(kem.P256_Kyber512)
	P384_Kyber768  CurveID = CurveID(kem.P384_Kyber768)
	P521_Kyber1024 CurveID = CurveID(kem.P521_Kyber1024)

	P256_LightSaber_KEM CurveID = CurveID(kem.P256_LightSaber_KEM)
	P384_Saber_KEM      CurveID = CurveID(kem.P384_Saber_KEM)
	P521_FireSaber_KEM  CurveID = CurveID(kem.P521_FireSaber_KEM)

	P256_NTRU_HPS_2048_509 CurveID = CurveID(kem.P256_NTRU_HPS_2048_509)
	P384_NTRU_HPS_2048_677 CurveID = CurveID(kem.P384_NTRU_HPS_2048_677)
	P521_NTRU_HPS_4096_821 CurveID = CurveID(kem.P521_NTRU_HPS_4096_821)

	P521_NTRU_HPS_4096_1229 CurveID = CurveID(kem.P521_NTRU_HPS_4096_1229)

	P384_NTRU_HRSS_701  CurveID = CurveID(kem.P384_NTRU_HRSS_701)
	P521_NTRU_HRSS_1373 CurveID = CurveID(kem.P521_NTRU_HPS_4096_821)

	// Liboqs PQC
	OQS_Kyber512  CurveID = CurveID(kem.OQS_Kyber512)
	OQS_Kyber768  CurveID = CurveID(kem.OQS_Kyber768)
	OQS_Kyber1024 CurveID = CurveID(kem.OQS_Kyber1024)

	LightSaber_KEM CurveID = CurveID(kem.LightSaber_KEM)
	Saber_KEM      CurveID = CurveID(kem.LightSaber_KEM)
	FireSaber_KEM  CurveID = CurveID(kem.FireSaber_KEM)

	NTRU_HPS_2048_509 CurveID = CurveID(kem.NTRU_HPS_2048_509)
	NTRU_HPS_2048_677 CurveID = CurveID(kem.NTRU_HPS_2048_677)
	NTRU_HPS_4096_821 CurveID = CurveID(kem.NTRU_HPS_4096_821)

	NTRU_HPS_4096_1229 CurveID = CurveID(kem.NTRU_HPS_4096_1229)

	NTRU_HRSS_701  CurveID = CurveID(kem.NTRU_HRSS_701)
	NTRU_HRSS_1373 CurveID = CurveID(kem.NTRU_HRSS_1373)

	P256_Classic_McEliece_348864 CurveID = CurveID(kem.P256_Classic_McEliece_348864)
)

var StringToCurveIDMap = map[string]CurveID {
	"P256": CurveP256, "P384": CurveP384, "P521": CurveP521,
	"Kyber512": OQS_Kyber512, "P256_Kyber512": P256_Kyber512,
	"Kyber768": OQS_Kyber768, "P384_Kyber768": P384_Kyber768,
	"Kyber1024": OQS_Kyber1024, "P521_Kyber1024": P521_Kyber1024,
	"LightSaber_KEM": LightSaber_KEM, "P256_LightSaber_KEM": P256_LightSaber_KEM,
	"Saber_KEM": Saber_KEM, "P384_Saber_KEM": P384_Saber_KEM,
	"FireSaber_KEM": FireSaber_KEM, "P521_FireSaber_KEM": P521_FireSaber_KEM,
	"NTRU_HPS_2048_509": NTRU_HPS_2048_509, "P256_NTRU_HPS_2048_509": P256_NTRU_HPS_2048_509,
	"NTRU_HPS_2048_677": NTRU_HPS_2048_677, "P384_NTRU_HPS_2048_677": P384_NTRU_HPS_2048_677,
	"NTRU_HPS_4096_821": NTRU_HPS_4096_821, "P521_NTRU_HPS_4096_821": P521_NTRU_HPS_4096_821,
	"NTRU_HPS_4096_1229": NTRU_HPS_4096_1229, "P521_NTRU_HPS_4096_1229": P521_NTRU_HPS_4096_1229,
	"NTRU_HRSS_701": NTRU_HRSS_701, "P384_NTRU_HRSS_701": P384_NTRU_HRSS_701,
	"NTRU_HRSS_1373": NTRU_HRSS_1373, "P521_NTRU_HRSS_1373": P521_NTRU_HRSS_1373,
	"P256_Classic-McEliece-348864": P256_Classic_McEliece_348864,
}

func CurveIDToString(curve CurveID) string {
	for key, value := range StringToCurveIDMap {
		if value == curve {
			return key
		}
	}
	return ""
}

func (curve CurveID) isKEM() bool {
	switch curve {
	case SIKEp434, Kyber512, CurveID(kem.IsLiboqs(kem.ID(curve))):
		return true
	}
	return false
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID
	data  []byte
}

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const (
	pskModePlain uint8 = 0
	pskModeDHE   uint8 = 1
)

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
)

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
const (
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
	signatureEd448
	signatureEdDilithium3
	signatureEdDilithium4
	authKEMTLS // for the KEMTLS
	authPQTLSLiboqs
)

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed, and that the input should be signed directly. It is the
// hash function associated with the Ed25519 signature scheme.
var directSigning crypto.Hash = 0

// supportedSignatureAlgorithms contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
var supportedSignatureAlgorithms = []SignatureScheme{
	PSSWithSHA256,
	ECDSAWithP256AndSHA256,
	Ed25519,
	PSSWithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA256,
	PKCS1WithSHA384,
	PKCS1WithSHA512,
	ECDSAWithP384AndSHA384,
	ECDSAWithP521AndSHA512,
	PKCS1WithSHA1,
	ECDSAWithSHA1,
	// Liboqs Hybrids
	KEMTLSWithP256_Kyber512, KEMTLSWithP384_Kyber768, KEMTLSWithP521_Kyber1024, KEMTLSWithP256_LightSaber_KEM, KEMTLSWithP384_Saber_KEM, KEMTLSWithP521_FireSaber_KEM, 
	KEMTLSWithP256_NTRU_HPS_2048_509, KEMTLSWithP384_NTRU_HPS_2048_677, KEMTLSWithP521_NTRU_HPS_4096_821, KEMTLSWithP521_NTRU_HPS_4096_1229, 
	KEMTLSWithP384_NTRU_HRSS_701, KEMTLSWithP521_NTRU_HRSS_1373, KEMTLSWithP256_Classic_McEliece_348864,

	// Liboqs PQC
	KEMTLSWithOQS_Kyber512, KEMTLSWithOQS_Kyber768, KEMTLSWithOQS_Kyber1024, KEMTLSWithLightSaber_KEM, KEMTLSWithSaber_KEM, KEMTLSWithFireSaber_KEM, 
	KEMTLSWithNTRU_HPS_2048_509, KEMTLSWithNTRU_HPS_2048_677, KEMTLSWithNTRU_HPS_4096_821, KEMTLSWithNTRU_HPS_4096_1229, KEMTLSWithNTRU_HRSS_701, KEMTLSWithNTRU_HRSS_1373,	

	// Liboqs Signature
	PQTLS_P256_Dilithium2, PQTLS_P256_Falcon512, PQTLS_P256_RainbowIClassic, PQTLS_P384_Dilithium3, PQTLS_P384_RainbowIIIClassic, PQTLS_P521_Dilithium5, PQTLS_P521_Falcon1024, PQTLS_P521_RainbowVClassic,
	PQTLS_Dilithium2, PQTLS_Falcon512, PQTLS_Dilithium3, PQTLS_P521_Dilithium5, PQTLS_P521_Falcon1024,

}

// supportedSignatureAlgorithmsDC contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.3 ClientHello and in a TLS 1.3
// CertificateRequest. This excludes 'rsa_pss_rsae_' algorithms.
var supportedSignatureAlgorithmsDC = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	Ed25519,
	Ed448,
	ECDSAWithP384AndSHA384,
	ECDSAWithP521AndSHA512,

	// authentication algorithms for KEMTLS. They are restricted for usage with Delegated
	// Credentials.
	KEMTLSWithKyber512,
	KEMTLSWithSIKEp434,

	// authentication algorithms for PQTLS. They are restricted for usage with Delegated
	// Credentials.
	PQTLSWithDilithium3,
	PQTLSWithDilithium4,

	// Liboqs Hybrids
	KEMTLSWithP256_Kyber512, KEMTLSWithP384_Kyber768, KEMTLSWithP521_Kyber1024, KEMTLSWithP256_LightSaber_KEM, KEMTLSWithP384_Saber_KEM, KEMTLSWithP521_FireSaber_KEM, 
	KEMTLSWithP256_NTRU_HPS_2048_509, KEMTLSWithP384_NTRU_HPS_2048_677, KEMTLSWithP521_NTRU_HPS_4096_821, KEMTLSWithP521_NTRU_HPS_4096_1229, 
	KEMTLSWithP384_NTRU_HRSS_701, KEMTLSWithP521_NTRU_HRSS_1373, KEMTLSWithP256_Classic_McEliece_348864,

	// Liboqs PQC
	KEMTLSWithOQS_Kyber512, KEMTLSWithOQS_Kyber768, KEMTLSWithOQS_Kyber1024, KEMTLSWithLightSaber_KEM, KEMTLSWithSaber_KEM, KEMTLSWithFireSaber_KEM, 
	KEMTLSWithNTRU_HPS_2048_509, KEMTLSWithNTRU_HPS_2048_677, KEMTLSWithNTRU_HPS_4096_821, KEMTLSWithNTRU_HPS_4096_1229, KEMTLSWithNTRU_HRSS_701, KEMTLSWithNTRU_HRSS_1373,	
}

// helloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
var helloRetryRequestRandom = []byte{ // See RFC 8446, Section 4.1.3.
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

// testingOnlyForceDowngradeCanary is set in tests to force the server side to
// include downgrade canaries even if it's using its highers supported version.
var testingOnlyForceDowngradeCanary bool

// testingTriggerHRR causes the server to intentionally trigger a
// HelloRetryRequest (HRR). This is useful for testing new TLS features that
// change the HRR codepath.
var testingTriggerHRR bool

// testingECHTriggerBypassAfterHRR causes the client to bypass ECH after HRR.
// If available, the client will offer ECH in the first CH only.
var testingECHTriggerBypassAfterHRR bool

// testingECHTriggerBypassBeforeHRR causes the client to bypass ECH before HRR.
// The client will offer ECH in the second CH only.
var testingECHTriggerBypassBeforeHRR bool

// testingECHIllegalHandleAfterHRR causes the client to illegally change the ECH
// extension after HRR.
var testingECHIllegalHandleAfterHRR bool

// testingECHTriggerPayloadDecryptError causes the client to to send an
// inauthentic payload.
var testingECHTriggerPayloadDecryptError bool

// testingECHOuterExtMany causes a client to incorporate a sequence of
// outer extensions into the ClientHelloInner when it offers the ECH extension.
// The "key_share" extension is the only incorporated extension by default.
var testingECHOuterExtMany bool

// testingECHOuterExtNone causes a client to not use the "outer_extension"
// mechanism for ECH. The "key_shares" extension is incorporated by default.
var testingECHOuterExtNone bool

// testingECHOuterExtIncorrectOrder causes the client to send the
// "outer_extension" extension in the wrong order when offering the ECH
// extension.
var testingECHOuterExtIncorrectOrder bool

// testingECHOuterIsInner causes the client to send the "ech_is_inner" extension
// in the ClientHelloOuter.
var testingECHOuterIsInner bool

// testingECHOuterExtIllegal causes the client to send in its
// "outer_extension" extension the codepoint for the ECH extension.
var testingECHOuterExtIllegal bool

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection (e.g. VersionTLS12).
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool

	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	CipherSuite uint16

	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	NegotiatedProtocol string

	// NegotiatedProtocolIsMutual used to indicate a mutual NPN negotiation.
	//
	// Deprecated: this value is always true.
	NegotiatedProtocolIsMutual bool

	// ServerName is the value of the Server Name Indication extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string

	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	PeerCertificates []*x509.Certificate

	// VerifiedChains is a list of one or more chains where the first element is
	// PeerCertificates[0] and the last element is from Config.RootCAs (on the
	// client side) or Config.ClientCAs (on the server side).
	//
	// On the client side, it's set if Config.InsecureSkipVerify is false. On
	// the server side, it's set if Config.ClientAuth is VerifyClientCertIfGiven
	// (and the peer provided a certificate) or RequireAndVerifyClientCert.
	VerifiedChains [][]*x509.Certificate

	// VerifiedDC indicates that the Delegated Credential sent by the peer (if advertised
	// and correctly processed), which has been verified against the leaf certificate,
	// has been used.
	VerifiedDC bool

	// DidClientAuthentiation states that the connection used client authentication.
	DidClientAuthentication bool

	// DidKEMTLS states that the connection was established by using KEMTLS.
	DidKEMTLS bool

	// DidPQTLS states that the connection was established by using PQTLS.
	DidPQTLS bool

	// CertificateMessage contains the server's Certificate Message.
	CertificateMessage []byte

	// CertificateReqMessage contains the server's Certificate Request Message.
	CertificateReqMessage []byte

	// SignedCertificateTimestamps is a list of SCTs provided by the peer
	// through the TLS handshake for the leaf certificate, if any.
	SignedCertificateTimestamps [][]byte

	// OCSPResponse is a stapled Online Certificate Status Protocol (OCSP)
	// response provided by the peer for the leaf certificate, if any.
	OCSPResponse []byte

	// TLSUnique contains the "tls-unique" channel binding value (see RFC 5929,
	// Section 3). This value will be nil for TLS 1.3 connections and for all
	// resumed connections.
	//
	// Deprecated: there are conditions in which this value might not be unique
	// to a connection. See the Security Considerations sections of RFC 5705 and
	// RFC 7627, and https://mitls.org/pages/attacks/3SHAKE#channelbindings.
	TLSUnique []byte

	// ECHAccepted is set if the ECH extension was offered by the client and
	// accepted by the server.
	ECHAccepted bool

	// CFControl is used to pass additional TLS configuration information to
	// HTTP requests.
	//
	// NOTE: This feature is used to implement Cloudflare-internal features.
	// This feature is unstable and applications MUST NOT depend on it.
	CFControl interface{}

	// ekm is a closure exposed via ExportKeyingMaterial.
	ekm func(label string, context []byte, length int) ([]byte, error)

	ClientHandshakeSizes TLS13ClientHandshakeSizes
	ServerHandshakeSizes TLS13ServerHandshakeSizes
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705. If context is nil, it is not used as part of
// the seed. If the connection was set to allow renegotiation via
// Config.Renegotiation, this function will return an error.
func (cs *ConnectionState) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	return cs.ekm(label, context, length)
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
)

// requiresClientCert reports whether the ClientAuthType requires a client
// certificate to be provided.
func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert:
		return true
	default:
		return false
	}
}

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type ClientSessionState struct {
	sessionTicket      []uint8               // Encrypted ticket used for session resumption with server
	vers               uint16                // TLS version negotiated for the session
	cipherSuite        uint16                // Ciphersuite negotiated for the session
	masterSecret       []byte                // Full handshake MasterSecret, or TLS 1.3 resumption_master_secret
	serverCertificates []*x509.Certificate   // Certificate chain presented by the server
	verifiedChains     [][]*x509.Certificate // Certificate chains we built for verification
	receivedAt         time.Time             // When the session ticket was received from the server
	ocspResponse       []byte                // Stapled OCSP response presented by the server
	scts               [][]byte              // SCTs presented by the server

	// TLS 1.3 fields.
	nonce  []byte    // Ticket nonce sent by the server, to derive PSK
	useBy  time.Time // Expiration of the ticket lifetime as set by the server
	ageAdd uint32    // Random obfuscation factor for sending the ticket age
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Up to TLS 1.2, only ticket-based resumption is supported, not
// SessionID-based resumption. In TLS 1.3 they were merged into PSK modes, which
// are supported via this interface.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key. It might
	// get called multiple times in a connection if a TLS 1.3 server provides
	// more than one session ticket. If called with a nil *ClientSessionState,
	// it should remove the cache entry.
	Put(sessionKey string, cs *ClientSessionState)
}

//go:generate stringer -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms.
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	// EdDSA algorithms.
	Ed25519 SignatureScheme = 0x0807
	Ed448   SignatureScheme = 0x0808

	// Legacy signature and hash algorithms for TLS 1.2.
	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203

	// KEMTLS algorithms for the Post-Quantum Cryptography experiment.
	// NOTE: Do not use outside of the experiment.
	KEMTLSWithSIKEp434 SignatureScheme = 0xfe00
	KEMTLSWithKyber512 SignatureScheme = 0xfe01

	// PQTLS algorithms for the Post-Quantum Cryptography experiment.
	// NOTE: Do not use outside of the experiment.
	PQTLSWithDilithium3 SignatureScheme = 0xfe61
	PQTLSWithDilithium4 SignatureScheme = 0xfe62

	// Liboqs Hybrids
	KEMTLSWithP256_Kyber512 SignatureScheme = 0xfe6b
	KEMTLSWithP384_Kyber768 SignatureScheme = 0xfe6c
	KEMTLSWithP521_Kyber1024 SignatureScheme = 0xfe6d 
	KEMTLSWithP256_LightSaber_KEM SignatureScheme = 0xfe6e
	KEMTLSWithP384_Saber_KEM SignatureScheme = 0xfe6f
	KEMTLSWithP521_FireSaber_KEM SignatureScheme = 0xfe70 
	KEMTLSWithP256_NTRU_HPS_2048_509 SignatureScheme = 0xfe71 
	KEMTLSWithP384_NTRU_HPS_2048_677 SignatureScheme = 0xfe72
	KEMTLSWithP521_NTRU_HPS_4096_821 SignatureScheme = 0xfe73
	KEMTLSWithP521_NTRU_HPS_4096_1229 SignatureScheme = 0xfe74
	KEMTLSWithP384_NTRU_HRSS_701 SignatureScheme = 0xfe75
	KEMTLSWithP521_NTRU_HRSS_1373 SignatureScheme = 0xfe76

	// Liboqs PQC	
	KEMTLSWithOQS_Kyber512 SignatureScheme = 0xfe6c
	KEMTLSWithOQS_Kyber768 SignatureScheme = 0xfe6d
	KEMTLSWithOQS_Kyber1024 SignatureScheme = 0xfe6e
	KEMTLSWithLightSaber_KEM SignatureScheme = 0xfe6f
	KEMTLSWithSaber_KEM SignatureScheme = 0xfe70
	KEMTLSWithFireSaber_KEM SignatureScheme = 0xfe71
	KEMTLSWithNTRU_HPS_2048_509 SignatureScheme = 0xfe72
	KEMTLSWithNTRU_HPS_2048_677 SignatureScheme = 0xfe73
	KEMTLSWithNTRU_HPS_4096_821 SignatureScheme = 0xfe74
	KEMTLSWithNTRU_HPS_4096_1229 SignatureScheme = 0xfe75
	KEMTLSWithNTRU_HRSS_701 SignatureScheme = 0xfe76
	KEMTLSWithNTRU_HRSS_1373 SignatureScheme = 0xfe77

	// Liboqs Hybrid Signatures
	PQTLS_P256_Dilithium2 SignatureScheme = 0xfe78
	PQTLS_P256_Falcon512 SignatureScheme = 0xfe79
	PQTLS_P256_RainbowIClassic SignatureScheme = 0xfe7a
	PQTLS_P384_Dilithium3 SignatureScheme = 0xfe7b
	PQTLS_P384_RainbowIIIClassic SignatureScheme = 0xfe7c
	PQTLS_P521_Dilithium5 SignatureScheme = 0xfe7d
	PQTLS_P521_Falcon1024 SignatureScheme = 0xfe7e
	PQTLS_P521_RainbowVClassic SignatureScheme = 0xfe7f

	KEMTLSWithP256_Classic_McEliece_348864 SignatureScheme = 0xfe80

	// Liboqs PQ-Only Signatures
	PQTLS_Dilithium2 SignatureScheme = 0xfe81
	PQTLS_Falcon512 SignatureScheme = 0xfe82
	
	PQTLS_Dilithium3 SignatureScheme = 0xfe83
	
	PQTLS_Dilithium5 SignatureScheme = 0xfe84
	PQTLS_Falcon1024 SignatureScheme = 0xfe85
)

// Liboqs Hybrids

// Hybrid KEMTLS Authentication
var liboqsSignatureSchemeMap = map[kem.ID]SignatureScheme{
	kem.P256_Kyber512: KEMTLSWithP256_Kyber512, kem.P384_Kyber768: KEMTLSWithP384_Kyber768, kem.P521_Kyber1024: KEMTLSWithP521_Kyber1024,
	kem.P256_LightSaber_KEM: KEMTLSWithP256_LightSaber_KEM, kem.P384_Saber_KEM: KEMTLSWithP384_Saber_KEM, kem.P521_FireSaber_KEM: KEMTLSWithP521_FireSaber_KEM,
	kem.P256_NTRU_HPS_2048_509: KEMTLSWithP256_NTRU_HPS_2048_509, kem.P384_NTRU_HPS_2048_677: KEMTLSWithP384_NTRU_HPS_2048_677, kem.P521_NTRU_HPS_4096_821: KEMTLSWithP521_NTRU_HPS_4096_821, kem.P521_NTRU_HPS_4096_1229: KEMTLSWithP521_NTRU_HPS_4096_1229,
	kem.P384_NTRU_HRSS_701: KEMTLSWithP384_NTRU_HRSS_701, kem.P521_NTRU_HRSS_1373: KEMTLSWithP521_NTRU_HRSS_1373, kem.P256_Classic_McEliece_348864: KEMTLSWithP256_Classic_McEliece_348864,
	kem.OQS_Kyber512: KEMTLSWithOQS_Kyber512, kem.OQS_Kyber768: KEMTLSWithOQS_Kyber768, kem.OQS_Kyber1024: KEMTLSWithOQS_Kyber1024, 
	kem.LightSaber_KEM: KEMTLSWithLightSaber_KEM, kem.Saber_KEM: KEMTLSWithSaber_KEM, kem.FireSaber_KEM: KEMTLSWithFireSaber_KEM, 
	kem.NTRU_HPS_2048_509: KEMTLSWithNTRU_HPS_2048_509, kem.NTRU_HPS_2048_677: KEMTLSWithNTRU_HPS_2048_677, kem.NTRU_HPS_4096_821: KEMTLSWithNTRU_HPS_4096_821, 
	kem.NTRU_HPS_4096_1229: KEMTLSWithNTRU_HPS_4096_1229, kem.NTRU_HRSS_701: KEMTLSWithNTRU_HRSS_701, kem.NTRU_HRSS_1373: KEMTLSWithNTRU_HRSS_1373,
}

func isLiboqsKEMSignature(scheme SignatureScheme) SignatureScheme {
	if scheme >= KEMTLSWithP256_Kyber512 && scheme <= KEMTLSWithNTRU_HRSS_1373 {
		return scheme
	}
	return 0
}

func liboqsKEMFromSignature(scheme SignatureScheme) kem.ID {
	for key, value := range liboqsSignatureSchemeMap {
		if value == scheme {
			return key
		}
	}
	return 0
}


// Hybrid PQTLS Authentication

var liboqsSigSignatureSchemeMap = map[liboqs_sig.ID]SignatureScheme {
	liboqs_sig.P256_Dilithium2: PQTLS_P256_Dilithium2, liboqs_sig.P256_Falcon512: PQTLS_P256_Falcon512, liboqs_sig.P256_RainbowIClassic: PQTLS_P256_RainbowIClassic, 
	liboqs_sig.P384_Dilithium3: PQTLS_P384_Dilithium3, liboqs_sig.P384_RainbowIIIClassic: PQTLS_P384_RainbowIIIClassic, 
	liboqs_sig.P521_Dilithium5: PQTLS_P521_Dilithium5, liboqs_sig.P521_Falcon1024: PQTLS_P521_Falcon1024, liboqs_sig.P521_RainbowVClassic: PQTLS_P521_RainbowVClassic,
	
	liboqs_sig.Dilithium2: PQTLS_Dilithium2, liboqs_sig.Falcon512: PQTLS_Falcon512,
	liboqs_sig.Dilithium3: PQTLS_Dilithium3,
	liboqs_sig.Dilithium5: PQTLS_Dilithium5, liboqs_sig.Falcon1024: PQTLS_Falcon1024,
}

func isLiboqsSigSignature(scheme SignatureScheme) SignatureScheme {
	if scheme >= PQTLS_P256_Dilithium2 && scheme <= PQTLS_Falcon1024 {
		return scheme
	}
	return 0
}

func classicFromHybridSig(scheme SignatureScheme) SignatureScheme {
	switch true {
	case scheme >= PQTLS_P256_Dilithium2 && scheme <= PQTLS_P256_RainbowIClassic:
		return ECDSAWithP256AndSHA256
	case scheme >= PQTLS_P384_Dilithium3 && scheme <= PQTLS_P384_RainbowIIIClassic:
		return ECDSAWithP384AndSHA384
	case scheme >= PQTLS_P521_Dilithium5 && scheme <= PQTLS_P521_RainbowVClassic:
		return ECDSAWithP521AndSHA512
	default:
		return 0
	}
}



func (scheme SignatureScheme) isKEMTLS() bool {
	switch scheme {
	case KEMTLSWithSIKEp434, KEMTLSWithKyber512, isLiboqsKEMSignature(scheme):
		return true
	default:
		return false
	}
}

func (scheme SignatureScheme) isPQTLS() bool {
	switch scheme {
	case PQTLSWithDilithium3, PQTLSWithDilithium4, isLiboqsSigSignature(scheme):
		return true
	default:
		return false
	}
}

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// SupportedCurves lists the elliptic curves supported by the client.
	// SupportedCurves is set only if the Supported Elliptic Curves
	// Extension is being used (see RFC 4492, Section 5.1.1).
	SupportedCurves []CurveID

	// SupportedPoints lists the point formats supported by the client.
	// SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see RFC 4492, Section 5.1.2).
	SupportedPoints []uint8

	// SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	SignatureSchemes []SignatureScheme

	// SignatureSchemesDC lists the signature schemes that the client
	// is willing to verify when using Delegated Credentials.
	// This is and can be different from SignatureSchemes. SignatureSchemesDC
	// is set only if the DelegatedCredentials Extension is being used.
	// If Delegated Credentials are supported, this list should not be nil.
	SignatureSchemesDC []SignatureScheme

	// SupportedProtos lists the application protocols supported by the client.
	// SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	SupportedProtos []string

	// SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// SupportDelegatedCredential is true if the client indicated willingness
	// to negotiate the Delegated Credential extension.
	SupportsDelegatedCredential bool

	// CachedInformationCert is true if the client has the server's certificate
	// message cached for the cached information extension.
	CachedInformationCert bool
	// CachedInformationCertReq is true if the client has the server's certificate
	// request message cached for the cached information extension.
	CachedInformationCertReq bool
	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// config is embedded by the GetCertificate or GetConfigForClient caller,
	// for use with SupportsCertificate.
	config *Config
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	// SupportDelegatedCredential is true if the server indicated willingness
	// to negotiate the Delegated Credential extension.
	SupportsDelegatedCredential bool

	// SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	SignatureSchemes []SignatureScheme

	// SignatureSchemesDC lists the signature schemes that the server
	// is willing to verify when using Delegated Credentials.
	// This is and can be different from SignatureSchemes. SignatureSchemesDC
	// is set only if the DelegatedCredentials Extension is being used.
	// If Delegated Credentials are supported, this list should not be nil.
	SignatureSchemesDC []SignatureScheme

	// Version is the TLS version that was negotiated for this connection.
	Version uint16
}

// RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
type RenegotiationSupport int

const (
	// RenegotiateNever disables renegotiation.
	RenegotiateNever RenegotiationSupport = iota

	// RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	RenegotiateOnceAsClient

	// RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	RenegotiateFreelyAsClient
)

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	// NOTE: it also provides a source of randomness for kemtls encapsulation
	// mechanisms.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains to present to the
	// other side of the connection. The first certificate compatible with the
	// peer's requirements is selected automatically.
	//
	// Server configurations must set one of Certificates, GetCertificate or
	// GetConfigForClient. Clients doing client-authentication may set either
	// Certificates or GetClientCertificate.
	//
	// Note: if there are multiple Certificates, and they don't have the
	// optional field Leaf set, certificate selection will incur a significant
	// per-handshake performance cost.
	Certificates []Certificate

	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	//
	// Deprecated: NameToCertificate only allows associating a single
	// certificate with a given name. Leave this field nil to let the library
	// select the first compatible chain from Certificates.
	NameToCertificate map[string]*Certificate

	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// best element of Certificates will be used.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	//
	// GetClientCertificate may be called multiple times for the same
	// connection if renegotiation occurs or if TLS 1.3 is in use.
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// If SessionTicketKey was explicitly set on the returned Config, or if
	// SetSessionTicketKeys was called on the returned Config, those keys will
	// be used. Otherwise, the original Config keys will be used (and possibly
	// rotated if they are automatically managed).
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify, or (for a server) when ClientAuth is
	// RequestClientCert or RequireAnyClientCert, then this callback will
	// be considered but the verifiedChains argument will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection, if not nil, is called after normal certificate
	// verification and after VerifyPeerCertificate by either a TLS client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections
	// regardless of InsecureSkipVerify or ClientAuth settings.
	VerifyConnection func(ConnectionState) error

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos is a list of supported application level protocols, in
	// order of preference.
	NextProtos []string

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	ServerName string

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
	// accepts any certificate presented by the server and any host name in that
	// certificate. In this mode, TLS is susceptible to machine-in-the-middle
	// attacks unless custom verification is used. This should be used only for
	// testing or in combination with VerifyConnection or VerifyPeerCertificate.
	InsecureSkipVerify bool

	// CipherSuites is a list of supported cipher suites for TLS versions up to
	// TLS 1.2. If CipherSuites is nil, a default list of secure cipher suites
	// is used, with a preference order based on hardware performance. The
	// default cipher suites might change over Go versions. Note that TLS 1.3
	// ciphersuites are not configurable.
	CipherSuites []uint16

	// PreferServerCipherSuites controls whether the server selects the
	// client's most preferred ciphersuite, or the server's most preferred
	// ciphersuite. If true then the server's preference, as expressed in
	// the order of elements in CipherSuites, is used.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket and
	// PSK (resumption) support. Note that on clients, session ticket support is
	// also disabled if ClientSessionCache is nil. On clients or servers,
	// support is disabled if the ECH extension is enabled.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session resumption.
	// See RFC 5077 and the PSK mode of RFC 8446. If zero, it will be filled
	// with random data before the first server handshake.
	//
	// Deprecated: if this field is left at zero, session ticket keys will be
	// automatically rotated every day and dropped after seven days. For
	// customizing the rotation schedule or synchronizing servers that are
	// terminating connections for the same host, use SetSessionTicketKeys.
	SessionTicketKey [32]byte

	// ClientSessionCache is a cache of ClientSessionState entries for TLS
	// session resumption. It is only used by clients.
	ClientSessionCache ClientSessionCache

	// MinVersion contains the minimum TLS version that is acceptable.
	// If zero, TLS 1.0 is currently taken as the minimum.
	MinVersion uint16

	// MaxVersion contains the maximum TLS version that is acceptable.
	// If zero, the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	MaxVersion uint16

	// CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used. The client will use the first preference as the type for
	// its key share in TLS 1.3. This may change in the future.
	CurvePreferences []CurveID

	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer

	// ECHEnabled determines whether the ECH extension is enabled for this
	// connection.
	ECHEnabled bool

	// WrappedCertEnabled determines whether the Wrapped Cert implementation is enabled for this
	// connection.
	WrappedCertEnabled bool

	IgnoreSigAlg bool

	// WrappedCertsDir is the directory where the Wrapped Certificates are stored
	WrappedCertsDir string

	// ClientECHConfigs are the parameters used by the client when it offers the
	// ECH extension. If ECH is enabled, a suitable configuration is found, and
	// the client supports TLS 1.3, then it will offer ECH in this handshake.
	// Otherwise, if ECH is enabled, it will send a dummy ECH extension.
	ClientECHConfigs []ECHConfig

	// ServerECHProvider is the ECH provider used by the client-facing server
	// for the ECH extension. If the client offers ECH and TLS 1.3 is
	// negotiated, then the provider is used to compute the HPKE context
	// (draft-irtf-cfrg-hpke-07), which in turn is used to decrypt the extension
	// payload.
	ServerECHProvider ECHProvider

	// CFEventHandler, if set, is called by the client and server at various
	// points during the handshake to handle specific events. This is used
	// primarily for collecting metrics.
	//
	// NOTE: This feature is used to implement Cloudflare-internal features.
	// This feature is unstable and applications MUST NOT depend on it.
	CFEventHandler func(event CFEvent)

	// CFControl is used to pass additional TLS configuration information to
	// HTTP requests via ConnectionState.
	//
	// NOTE: This feature is used to implement Cloudflare-internal features.
	// This feature is unstable and applications MUST NOT depend on it.
	CFControl interface{}

	// SupportDelegatedCredential is true if the client or server is willing
	// to negotiate the delegated credential extension.
	// This can only be used with TLS 1.3.
	//
	// See https://tools.ietf.org/html/draft-ietf-tls-subcerts.
	SupportDelegatedCredential bool

	// KEMTLSEnabled is true if the client or server is willing
	// to start a KEMTLS handshake based on TLS 1.3.
	KEMTLSEnabled bool

	// PQTLSEnabled is true if the client or server is willing
	// to start a PQTLS handshake (PQ KEMs for confidentiality and PQ Signatures for
	// authentication based on TLS 1.3.
	PQTLSEnabled bool

	// CachedCert corresponds to a cached server's Certificate message by the
	// client. If filled, it will be used by the cached information extension.
	CachedCert []byte
	// CachedCertReq corresponds to a cached server's Certificate Request message
	// by the client. If filled, it will be used by the cached information extension.
	CachedCertReq []byte

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If set, it means the
	// the keys were set with SessionTicketKey or SetSessionTicketKeys. The
	// first key is used for new tickets and any subsequent keys can be used to
	// decrypt old tickets. The slice contents are not protected by the mutex
	// and are immutable.
	sessionTicketKeys []ticketKey
	// autoSessionTicketKeys is like sessionTicketKeys but is owned by the
	// auto-rotation logic. See Config.ticketKeys.
	autoSessionTicketKeys []ticketKey

	PSKDBPath string

	// Path to the client's truststore, where it stores trusted certificates
	TruststorePath string

	// Password of the client's truststore, where it stores trusted certificates
	TruststorePassword string

	// PreQuantumScenario is true if we are simulating a TLS handshake in the pre-quantum scenario
	// of the PKI Extended Lifetime Period proposal
	PreQuantumScenario bool
}

const (
	// ticketKeyNameLen is the number of bytes of identifier that is prepended to
	// an encrypted session ticket in order to identify the key used to encrypt it.
	ticketKeyNameLen = 16

	// ticketKeyLifetime is how long a ticket key remains valid and can be used to
	// resume a client connection.
	ticketKeyLifetime = 7 * 24 * time.Hour // 7 days

	// ticketKeyRotation is how often the server should rotate the session ticket key
	// that is used for new tickets.
	ticketKeyRotation = 24 * time.Hour
)

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	// keyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	keyName [ticketKeyNameLen]byte
	aesKey  [16]byte
	hmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	created time.Time
}

// ticketKeyFromBytes converts from the external representation of a session
// ticket key to a ticketKey. Externally, session ticket keys are 32 random
// bytes and this function expands that into sufficient name and key material.
func (c *Config) ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	copy(key.keyName[:], hashed[:ticketKeyNameLen])
	copy(key.aesKey[:], hashed[ticketKeyNameLen:ticketKeyNameLen+16])
	copy(key.hmacKey[:], hashed[ticketKeyNameLen+16:ticketKeyNameLen+32])
	key.created = c.time()
	return key
}

// maxSessionTicketLifetime is the maximum allowed lifetime of a TLS 1.3 session
// ticket, and the lifetime we set for tickets we send.
const maxSessionTicketLifetime = 7 * 24 * time.Hour

// Clone returns a shallow clone of c or nil if c is nil. It is safe to clone a Config that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		Rand:                        c.Rand,
		Time:                        c.Time,
		Certificates:                c.Certificates,
		NameToCertificate:           c.NameToCertificate,
		GetCertificate:              c.GetCertificate,
		GetClientCertificate:        c.GetClientCertificate,
		GetConfigForClient:          c.GetConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		VerifyConnection:            c.VerifyConnection,
		RootCAs:                     c.RootCAs,
		NextProtos:                  c.NextProtos,
		ServerName:                  c.ServerName,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		PreferServerCipherSuites:    c.PreferServerCipherSuites,
		SessionTicketsDisabled:      c.SessionTicketsDisabled,
		SessionTicketKey:            c.SessionTicketKey,
		ClientSessionCache:          c.ClientSessionCache,
		MinVersion:                  c.MinVersion,
		MaxVersion:                  c.MaxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		Renegotiation:               c.Renegotiation,
		KeyLogWriter:                c.KeyLogWriter,
		SupportDelegatedCredential:  c.SupportDelegatedCredential,
		KEMTLSEnabled:               c.KEMTLSEnabled,
		PQTLSEnabled:                c.PQTLSEnabled,
		CachedCert:                  c.CachedCert,
		CachedCertReq:               c.CachedCertReq,
		ECHEnabled:                  c.ECHEnabled,
		ClientECHConfigs:            c.ClientECHConfigs,
		ServerECHProvider:           c.ServerECHProvider,
		CFEventHandler:              c.CFEventHandler,
		CFControl:                   c.CFControl,
		sessionTicketKeys:           c.sessionTicketKeys,
		autoSessionTicketKeys:       c.autoSessionTicketKeys,
		WrappedCertEnabled:          c.WrappedCertEnabled,
		IgnoreSigAlg:                c.IgnoreSigAlg,
		PSKDBPath:                   c.PSKDBPath,
		TruststorePath: 						 c.TruststorePath,
		TruststorePassword: 				 c.TruststorePassword,
		PreQuantumScenario:          c.PreQuantumScenario,
	}
}

// deprecatedSessionTicketKey is set as the prefix of SessionTicketKey if it was
// randomized for backwards compatibility but is not in use.
var deprecatedSessionTicketKey = []byte("DEPRECATED")

// initLegacySessionTicketKeyRLocked ensures the legacy SessionTicketKey field is
// randomized if empty, and that sessionTicketKeys is populated from it otherwise.
func (c *Config) initLegacySessionTicketKeyRLocked() {
	// Don't write if SessionTicketKey is already defined as our deprecated string,
	// or if it is defined by the user but sessionTicketKeys is already set.
	if c.SessionTicketKey != [32]byte{} &&
		(bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) || len(c.sessionTicketKeys) > 0) {
		return
	}

	// We need to write some data, so get an exclusive lock and re-check any conditions.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.SessionTicketKey == [32]byte{} {
		if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
			panic(fmt.Sprintf("tls: unable to generate random session ticket key: %v", err))
		}
		// Write the deprecated prefix at the beginning so we know we created
		// it. This key with the DEPRECATED prefix isn't used as an actual
		// session ticket key, and is only randomized in case the application
		// reuses it for some reason.
		copy(c.SessionTicketKey[:], deprecatedSessionTicketKey)
	} else if !bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) && len(c.sessionTicketKeys) == 0 {
		c.sessionTicketKeys = []ticketKey{c.ticketKeyFromBytes(c.SessionTicketKey)}
	}

}

// ticketKeys returns the ticketKeys for this connection.
// If configForClient has explicitly set keys, those will
// be returned. Otherwise, the keys on c will be used and
// may be rotated if auto-managed.
// During rotation, any expired session ticket keys are deleted from
// c.sessionTicketKeys. If the session ticket key that is currently
// encrypting tickets (ie. the first ticketKey in c.sessionTicketKeys)
// is not fresh, then a new session ticket key will be
// created and prepended to c.sessionTicketKeys.
func (c *Config) ticketKeys(configForClient *Config) []ticketKey {
	// If the ConfigForClient callback returned a Config with explicitly set
	// keys, use those, otherwise just use the original Config.
	if configForClient != nil {
		configForClient.mutex.RLock()
		if configForClient.SessionTicketsDisabled {
			return nil
		}
		configForClient.initLegacySessionTicketKeyRLocked()
		if len(configForClient.sessionTicketKeys) != 0 {
			ret := configForClient.sessionTicketKeys
			configForClient.mutex.RUnlock()
			return ret
		}
		configForClient.mutex.RUnlock()
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.SessionTicketsDisabled {
		return nil
	}
	c.initLegacySessionTicketKeyRLocked()
	if len(c.sessionTicketKeys) != 0 {
		return c.sessionTicketKeys
	}
	// Fast path for the common case where the key is fresh enough.
	if len(c.autoSessionTicketKeys) > 0 && c.time().Sub(c.autoSessionTicketKeys[0].created) < ticketKeyRotation {
		return c.autoSessionTicketKeys
	}

	// autoSessionTicketKeys are managed by auto-rotation.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Re-check the condition in case it changed since obtaining the new lock.
	if len(c.autoSessionTicketKeys) == 0 || c.time().Sub(c.autoSessionTicketKeys[0].created) >= ticketKeyRotation {
		var newKey [32]byte
		if _, err := io.ReadFull(c.rand(), newKey[:]); err != nil {
			panic(fmt.Sprintf("unable to generate random session ticket key: %v", err))
		}
		valid := make([]ticketKey, 0, len(c.autoSessionTicketKeys)+1)
		valid = append(valid, c.ticketKeyFromBytes(newKey))
		for _, k := range c.autoSessionTicketKeys {
			// While rotating the current key, also remove any expired ones.
			if c.time().Sub(k.created) < ticketKeyLifetime {
				valid = append(valid, k)
			}
		}
		c.autoSessionTicketKeys = valid
	}
	return c.autoSessionTicketKeys
}

// SetSessionTicketKeys updates the session ticket keys for a server.
//
// The first key will be used when creating new tickets, while all keys can be
// used for decrypting tickets. It is safe to call this function while the
// server is running in order to rotate the session ticket keys. The function
// will panic if keys is empty.
//
// Calling this function will turn off automatic session ticket key rotation.
//
// If multiple servers are terminating connections for the same host they should
// all have the same session ticket keys. If the session ticket keys leaks,
// previously recorded and future TLS connections using those keys might be
// compromised.
func (c *Config) SetSessionTicketKeys(keys [][32]byte) {
	if len(keys) == 0 {
		panic("tls: keys must have at least one key")
	}

	newKeys := make([]ticketKey, len(keys))
	for i, bytes := range keys {
		newKeys[i] = c.ticketKeyFromBytes(bytes)
	}

	c.mutex.Lock()
	c.sessionTicketKeys = newKeys
	c.mutex.Unlock()
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

var supportedVersions = []uint16{
	VersionTLS13,
	VersionTLS12,
	VersionTLS11,
	VersionTLS10,
}

func (c *Config) supportedVersions() []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) supportedVersionsFromMin(minVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		if v < minVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) maxSupportedVersion() uint16 {
	supportedVersions := c.supportedVersions()
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use supportedVersions anyway.
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

var defaultCurvePreferences = []CurveID{X25519, CurveP256, CurveP384, CurveP521}
var defaultKEMPreferences = []CurveID{Kyber512, SIKEp434, X25519, CurveP256, CurveP384, CurveP521}

func (c *Config) curvePreferences() []CurveID {
	if c == nil || len(c.CurvePreferences) == 0 {
		if c.KEMTLSEnabled || c.PQTLSEnabled {
			return defaultKEMPreferences
		}

		return defaultCurvePreferences
	}
	return c.CurvePreferences
}

func (c *Config) supportsCurve(curve CurveID) bool {
	for _, cc := range c.curvePreferences() {
		if cc == curve {
			return true
		}
	}
	return false
}

// mutualVersion returns the protocol version to use given the advertised
// versions of the peer. Priority is given to the peer preference order.
func (c *Config) mutualVersion(peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions()
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

var errNoCertificates = errors.New("tls: no certificates configured")

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetCertificate != nil &&
		(len(c.Certificates) == 0 || len(clientHello.ServerName) > 0) {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificates
	}

	if len(c.Certificates) == 1 {
		// There's only one choice, so no point doing any work.
		return &c.Certificates[0], nil
	}

	if c.NameToCertificate != nil {
		name := strings.ToLower(clientHello.ServerName)
		if cert, ok := c.NameToCertificate[name]; ok {
			return cert, nil
		}
		if len(name) > 0 {
			labels := strings.Split(name, ".")
			labels[0] = "*"
			wildcardName := strings.Join(labels, ".")
			if cert, ok := c.NameToCertificate[wildcardName]; ok {
				return cert, nil
			}
		}
	}

	for _, cert := range c.Certificates {
		if err := clientHello.SupportsCertificate(&cert); err == nil {
			return &cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0], nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the client that sent the ClientHello. Otherwise, it returns an error
// describing the reason for the incompatibility.
//
// If this ClientHelloInfo was passed to a GetConfigForClient or GetCertificate
// callback, this method will take into account the associated Config. Note that
// if GetConfigForClient returns a different Config, the change can't be
// accounted for by this method.
//
// This function will call x509.ParseCertificate unless c.Leaf is set, which can
// incur a significant performance cost.
func (chi *ClientHelloInfo) SupportsCertificate(c *Certificate) error {
	// Note we don't currently support certificate_authorities nor
	// signature_algorithms_cert, and don't check the algorithms of the
	// signatures on the chain (which anyway are a SHOULD, see RFC 8446,
	// Section 4.4.2.2).

	config := chi.config
	if config == nil {
		config = &Config{}
	}
	vers, ok := config.mutualVersion(chi.SupportedVersions)
	if !ok {
		return errors.New("no mutually supported protocol versions")
	}

	// If the client specified the name they are trying to connect to, the
	// certificate needs to be valid for it.
	if chi.ServerName != "" {
		x509Cert, err := c.leaf()
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		if err := x509Cert.VerifyHostname(chi.ServerName); err != nil {
			return fmt.Errorf("certificate is not valid for requested server name: %w", err)
		}
	}

	// supportsRSAFallback returns nil if the certificate and connection support
	// the static RSA key exchange, and unsupported otherwise. The logic for
	// supporting static RSA is completely disjoint from the logic for
	// supporting signed key exchanges, so we just check it as a fallback.
	supportsRSAFallback := func(unsupported error) error {
		// TLS 1.3 dropped support for the static RSA key exchange.
		if vers == VersionTLS13 {
			return unsupported
		}
		// The static RSA key exchange works by decrypting a challenge with the
		// RSA private key, not by signing, so check the PrivateKey implements
		// crypto.Decrypter, like *rsa.PrivateKey does.
		if priv, ok := c.PrivateKey.(crypto.Decrypter); ok {
			if _, ok := priv.Public().(*rsa.PublicKey); !ok {
				return unsupported
			}
		} else {
			return unsupported
		}
		// Finally, there needs to be a mutual cipher suite that uses the static
		// RSA key exchange instead of ECDHE.
		rsaCipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
			if c.flags&suiteECDHE != 0 {
				return false
			}
			if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
				return false
			}
			return true
		})
		if rsaCipherSuite == nil {
			return unsupported
		}
		return nil
	}

	// If the client sent the signature_algorithms extension, ensure it supports
	// schemes we can use with this certificate and TLS version.
	if len(chi.SignatureSchemes) > 0 {
		if _, err := selectSignatureScheme(vers, c, chi.SignatureSchemes); err != nil {
			return supportsRSAFallback(err)
		}
	}

	// In TLS 1.3 we are done because supported_groups is only relevant to the
	// ECDHE computation, point format negotiation is removed, cipher suites are
	// only relevant to the AEAD choice, and static RSA does not exist.
	if vers == VersionTLS13 {
		return nil
	}

	// The only signed key exchange we support is ECDHE.
	if !supportsECDHE(config, chi.SupportedCurves, chi.SupportedPoints) {
		return supportsRSAFallback(errors.New("client doesn't support ECDHE, can only use legacy RSA key exchange"))
	}

	var ecdsaCipherSuite bool
	if priv, ok := c.PrivateKey.(crypto.Signer); ok {
		switch pub := priv.Public().(type) {
		case *ecdsa.PublicKey:
			var curve CurveID
			switch pub.Curve {
			case elliptic.P256():
				curve = CurveP256
			case elliptic.P384():
				curve = CurveP384
			case elliptic.P521():
				curve = CurveP521
			default:
				return supportsRSAFallback(unsupportedCertificateError(c))
			}
			var curveOk bool
			for _, c := range chi.SupportedCurves {
				if c == curve && config.supportsCurve(c) {
					curveOk = true
					break
				}
			}
			if !curveOk {
				return errors.New("client doesn't support certificate curve")
			}
			ecdsaCipherSuite = true
		case ed25519.PublicKey:
			if vers < VersionTLS12 || len(chi.SignatureSchemes) == 0 {
				return errors.New("connection doesn't support Ed25519")
			}
			ecdsaCipherSuite = true
		case *rsa.PublicKey:
		default:
			return supportsRSAFallback(unsupportedCertificateError(c))
		}
	} else {
		return supportsRSAFallback(unsupportedCertificateError(c))
	}

	// Make sure that there is a mutually supported cipher suite that works with
	// this certificate. Cipher suite selection will then apply the logic in
	// reverse to pick it. See also serverHandshakeState.cipherSuiteOk.
	cipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
		if c.flags&suiteECDHE == 0 {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !ecdsaCipherSuite {
				return false
			}
		} else {
			if ecdsaCipherSuite {
				return false
			}
		}
		if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
			return false
		}
		return true
	})
	if cipherSuite == nil {
		return supportsRSAFallback(errors.New("client doesn't support any cipher suites compatible with the certificate"))
	}

	return nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
func (cri *CertificateRequestInfo) SupportsCertificate(c *Certificate) error {
	if _, err := selectSignatureScheme(cri.Version, c, cri.SignatureSchemes); err != nil {
		return err
	}

	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		// Parse the certificate if this isn't the leaf node, or if
		// chain.Leaf was nil.
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}
	return errors.New("chain is not signed by an acceptable CA")
}

// BuildNameToCertificate parses c.Certificates and builds c.NameToCertificate
// from the CommonName and SubjectAlternateName fields of each of the leaf
// certificates.
//
// Deprecated: NameToCertificate only allows associating a single certificate
// with a given name. Leave that field nil to let the library select the first
// compatible chain from Certificates.
func (c *Config) BuildNameToCertificate() {
	c.NameToCertificate = make(map[string]*Certificate)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		x509Cert, err := cert.leaf()
		if err != nil {
			continue
		}
		// If SANs are *not* present, some clients will consider the certificate
		// valid for the name in the Common Name.
		if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
			c.NameToCertificate[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			c.NameToCertificate[san] = cert
		}
	}
}

const (
	keyLogLabelTLS12                           = "CLIENT_RANDOM"
	keyLogLabelClientHandshake                 = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake                 = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientKEMAuthenticatedHandshake = "CLIENT_AUTHENTICATED_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerKEMAuthenticatedHandshake = "SERVER_AUTHENTICATED_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic                   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic                   = "SERVER_TRAFFIC_SECRET_0"
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := []byte(fmt.Sprintf("%s %x %x\n", label, clientRandom, secret))

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
// and is only for debugging, so a global mutex saves space.
var writerMutex sync.Mutex

// A DelegatedCredentialPair contains a Delegated Credential and its
// associated private key.
type DelegatedCredentialPair struct {
	// DC is the delegated credential.
	DC *DelegatedCredential
	// PrivateKey is the private key used to derive the public key of
	// contained in DC. PrivateKey must implement crypto.Signer.
	PrivateKey crypto.PrivateKey
}

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey
	// SupportedSignatureAlgorithms is an optional list restricting what
	// signature algorithms the PrivateKey can be used for.
	SupportedSignatureAlgorithms []SignatureScheme
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	OCSPStaple []byte
	// SignedCertificateTimestamps contains an optional list of Signed
	// Certificate Timestamps which will be served to clients that request it.
	SignedCertificateTimestamps [][]byte
	// DelegatedCredentials are a list of Delegated Credentials with their
	// corresponding private keys, signed by the leaf certificate.
	// If there are no delegated credentials, this field is nil.
	DelegatedCredentials []DelegatedCredentialPair
	// DelegatedCredential is the delegated credential to be used in the
	// handshake.
	// If there are no delegated credentials, this field is nil.
	// NOTE: Do not fill this field, as it will be filled depending on
	// the provided list of delegated credentials.
	DelegatedCredential []byte
	// DelegatedCredentialPrivateKey contains the private key corresponding to the public key in
	// the Delegated Credential.
	// NOTE: Do not fill this field, as it will be filled depending on
	// the provided list of delegated credentials.
	DelegatedCredentialPrivateKey crypto.PrivateKey
	// Leaf is the parsed form of the leaf certificate, which may be initialized
	// using x509.ParseCertificate to reduce per-handshake processing. If nil,
	// the leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// leaf returns the parsed leaf certificate, either from c.Leaf or by parsing
// the corresponding c.Certificate[0].
func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

// lruSessionCache is a ClientSessionCache implementation that uses an LRU
// caching strategy.
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

// NewLRUClientSessionCache returns a ClientSessionCache with the given
// capacity that uses an LRU strategy. If capacity is < 1, a default capacity
// is used instead.
func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put adds the provided (sessionKey, cs) pair to the cache. If cs is nil, the entry
// corresponding to sessionKey is removed from the cache instead.
func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
		} else {
			entry := elem.Value.(*lruSessionCacheEntry)
			entry.state = cs
			c.q.MoveToFront(elem)
		}
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get returns the ClientSessionState value associated with a given key. It
// returns (nil, false) if no value is found.
func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

var (
	once                        sync.Once
	varDefaultCipherSuites      []uint16
	varDefaultCipherSuitesTLS13 []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func defaultCipherSuitesTLS13() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuitesTLS13
}

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X
)

func initDefaultCipherSuites() {
	var topCipherSuites []uint16

	if hasAESGCMHardwareSupport {
		// If AES-GCM hardware is provided then prioritise AES-GCM
		// cipher suites.
		topCipherSuites = []uint16{
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
		varDefaultCipherSuitesTLS13 = []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_AES_256_GCM_SHA384,
		}
	} else {
		// Without AES-GCM hardware, we put the ChaCha20-Poly1305
		// cipher suites first.
		topCipherSuites = []uint16{
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}
		varDefaultCipherSuitesTLS13 = []uint16{
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
		}
	}

	varDefaultCipherSuites = make([]uint16, 0, len(cipherSuites))
	varDefaultCipherSuites = append(varDefaultCipherSuites, topCipherSuites...)

NextCipherSuite:
	for _, suite := range cipherSuites {
		if suite.flags&suiteDefaultOff != 0 {
			continue
		}
		for _, existing := range varDefaultCipherSuites {
			if existing == suite.id {
				continue NextCipherSuite
			}
		}
		varDefaultCipherSuites = append(varDefaultCipherSuites, suite.id)
	}
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

func isSupportedSignatureAlgorithm(sigAlg SignatureScheme, supportedSignatureAlgorithms []SignatureScheme) bool {
	for _, s := range supportedSignatureAlgorithms {
		if s == sigAlg {
			return true
		}
	}
	return false
}

var aesgcmCiphers = map[uint16]bool{
	// 1.2
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	// 1.3
	TLS_AES_128_GCM_SHA256: true,
	TLS_AES_256_GCM_SHA384: true,
}

var nonAESGCMAEADCiphers = map[uint16]bool{
	// 1.2
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:   true,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: true,
	// 1.3
	TLS_CHACHA20_POLY1305_SHA256: true,
}

// aesgcmPreferred returns whether the first valid cipher in the preference list
// is an AES-GCM cipher, implying the peer has hardware support for it.
func aesgcmPreferred(ciphers []uint16) bool {
	for _, cID := range ciphers {
		c := cipherSuiteByID(cID)
		if c == nil {
			c13 := cipherSuiteTLS13ByID(cID)
			if c13 == nil {
				continue
			}
			return aesgcmCiphers[cID]
		}
		return aesgcmCiphers[cID]
	}
	return false
}

// deprioritizeAES reorders cipher preference lists by rearranging
// adjacent AEAD ciphers such that AES-GCM based ciphers are moved
// after other AEAD ciphers. It returns a fresh slice.
func deprioritizeAES(ciphers []uint16) []uint16 {
	reordered := make([]uint16, len(ciphers))
	copy(reordered, ciphers)
	sort.SliceStable(reordered, func(i, j int) bool {
		return nonAESGCMAEADCiphers[reordered[i]] && aesgcmCiphers[reordered[j]]
	})
	return reordered
}

// getMessageLength returns the handshake message length
func getMessageLength(msg []byte) (uint32, error) {
	var msg_size uint32
	
	s := cryptobyte.String(msg)
	if !s.Skip(1) || !s.ReadUint24(&msg_size) {
		return 0, errors.New("tls: couldn't get length of client hello message")
	}

	return msg_size, nil
}

func certPSKWriteToFile(peerIP string, pskLabelBytes, pskBytes []byte, isClient bool, pskDBPath string) error {

	pskLabel := hex.EncodeToString(pskLabelBytes)
	psk := hex.EncodeToString(pskBytes)

	fileName := pskDBPath

	csvFile, err := os.OpenFile(fileName, os.O_APPEND|os.O_RDWR, os.ModeAppend)
	if err != nil {
		return err
	}

	defer csvFile.Close()

	csvwriter := csv.NewWriter(csvFile)

	var rec []string

	if isClient {
		rec = []string{peerIP, pskLabel, psk} 
	} else {
		rec = []string{pskLabel, psk}
	}

	if err := csvwriter.Write(rec); err != nil {
		return err
	}
		
	csvwriter.Flush()	

	return nil
}

type certPSKExtension struct {
	establishPSK bool  // The client will set it to true when it wants to establish a new PSK
	identities [][]byte
}
