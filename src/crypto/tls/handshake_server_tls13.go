// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/kem"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// maxClientPSKIdentities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const maxClientPSKIdentities = 5

type serverHandshakeStateTLS13 struct {
	c            *Conn
	clientHello  *clientHelloMsg
	hello        *serverHelloMsg
	sentDummyCCS bool
	usingPSK     bool
	
	usingCachedInformation bool  // RFC 7924: Cached Information Extension
	certHash []byte              // RFC 7924: Cached Information Extension

	keyKEMShare        bool
	isKEMTLS           bool
	pdkKEMTLS          bool
	ssKEMTLS           []byte
	isClientAuthKEMTLS bool

	suite           *cipherSuiteTLS13
	cert            *Certificate
	sigAlg          SignatureScheme
	earlySecret     []byte
	sharedKey       []byte
	handshakeSecret []byte
	masterSecret    []byte
	trafficSecret   []byte // client_application_traffic_secret_0
	transcript      hash.Hash
	clientFinished  []byte
	certReq         *certificateRequestMsgTLS13

	certPSK         []byte
	handshakeTimings CFEventTLS13ServerHandshakeTimingInfo

	WrappedCertsDB map[string]Certificate
}

// processDelegatedCredentialFromClient unmarshals the DelegatedCredential
// offered by the client (if present) and validates it using the peer's
// certificate.
func (hs *serverHandshakeStateTLS13) processDelegatedCredentialFromClient(rawDC []byte, certVerifyMsg *certificateVerifyMsg) error {
	c := hs.c

	var dc *DelegatedCredential
	var err error
	if rawDC != nil {
		// Assert that the DC extension was indicated by the client.
		if !hs.certReq.supportDelegatedCredential {
			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: got Delegated Credential extension without indication")
		}

		dc, err = unmarshalDelegatedCredential(rawDC)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return fmt.Errorf("tls: Delegated Credential: %s", err)
		}

		if !isSupportedSignatureAlgorithm(dc.cred.expCertVerfAlgo, supportedSignatureAlgorithmsDC) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: Delegated Credential used with invalid signature algorithm")
		}
	}

	if dc != nil {
		if !dc.Validate(c.peerCertificates[0], true, c.config.time(), certVerifyMsg) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid Delegated Credential")
		}
	}

	c.verifiedDC = dc

	return nil
}

func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
	if err := hs.processClientHello(); err != nil {
		return err
	}
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	if err := hs.pickCertificate(); err != nil {
		return err
	}
	c.buffering = true
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if hs.isKEMTLS {
		// send application data for KEMTLS
		if !hs.pdkKEMTLS {
			if _, err := c.flush(); err != nil {
				return err
			}
			// second round of sending for KEMTLS
			hs.handshakeTimings.reset()
		}

		return hs.handshakeKEMTLS()
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	if !hs.pdkKEMTLS {
		// Note that at this point we could start sending application data without
		// waiting for the client's second flight, but the application might not
		// expect the lack of replay protection of the ClientHello parameters.
		if _, err := c.flush(); err != nil {
			return err
		}

		// second round of TLS1.3, thrid round for KEMTLS and fourth round for mKEMTLS
		hs.handshakeTimings.reset()
	}

	if err := hs.readClientCertificate(); err != nil {
		return err
	}
	if err := hs.readClientFinished(); err != nil {
		return err
	}

	//hs.handshakeTimings.ExperimentName = experimentName(c)
	// fmt.Printf("\n %+v \n", hs.handshakeTimings)
	hs.handshakeTimings.finish()
	c.handleCFEvent(hs.handshakeTimings)

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *serverHandshakeStateTLS13) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)

	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	hs.hello.supportedVersion = c.vers

	if len(hs.clientHello.supportedVersions) == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client used the legacy version field to negotiate TLS 1.3")
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if c.vers < c.config.maxSupportedVersion() {
				c.sendAlert(alertInappropriateFallback)
				return errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: TLS 1.3 client supports illegal compression methods")
	}

	if hs.clientHello.cachedInformationCert {

		// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
		if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
			return c.sendAlert(alertMissingExtension)
		}

		certificate, err := c.config.getCertificate(clientHelloInfo(c, hs.clientHello))
		if err != nil {
			if err == errNoCertificates {
				c.sendAlert(alertUnrecognizedName)
			} else {
				c.sendAlert(alertInternalError)
			}
			return err
		}

		hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
		if err != nil {
			// getCertificate returned a certificate that is unsupported or
			// incompatible with the client's signature algorithms.
			c.sendAlert(alertHandshakeFailure)
			return err
		}

		hs.cert = certificate

		if c.config.KEMTLSEnabled {			
			if hs.clientHello.delegatedCredentialSupported && len(hs.clientHello.supportedSignatureAlgorithmsDC) > 0 {
				delegatedCredentialPair, err := getDelegatedCredential(clientHelloInfo(c, hs.clientHello), hs.cert)
				if err != nil {
					// a Delegated Credential was not found. Fallback to the certificate.
					return nil
				}

				if delegatedCredentialPair.DC != nil && delegatedCredentialPair.PrivateKey != nil {
					// Even if the Delegated Credential has already been marshalled, be sure it is the correct one.
					delegatedCredentialPair.DC.raw, err = delegatedCredentialPair.DC.marshal()
					if err != nil {
						// invalid Delegated Credential. Fallback to the certificate.
						return nil
					}

					hs.sigAlg, err = selectSignatureSchemeDC(c.vers, delegatedCredentialPair.DC, hs.clientHello.supportedSignatureAlgorithmsDC)
					if err != nil {
						// the Delegated Credential is unsupported or
						// incompatible with the client's signature algorithms.
						// Fallback to the certificate.
						return nil
					}

					hs.cert.DelegatedCredentialPrivateKey = delegatedCredentialPair.PrivateKey
					hs.cert.DelegatedCredential = delegatedCredentialPair.DC.raw

					certMsg := new(certificateMsgTLS13)

					certMsg.certificate = *hs.cert
					certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
					certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
					certMsg.delegatedCredential = hs.clientHello.delegatedCredentialSupported && len(hs.cert.DelegatedCredential) > 0

					certMsgRaw := certMsg.marshal()
					cachedCertHash := calculateHashCachedInfo(certMsgRaw)
					if bytes.Equal(cachedCertHash, hs.clientHello.cachedInformationCertHash) {
						hs.hello.cachedInformationCert = true

						if delegatedCredentialPair.DC.cred.expCertVerfAlgo.isKEMTLS() {
							sk, ok1 := hs.cert.DelegatedCredentialPrivateKey.(*kem.PrivateKey)
							if !ok1 {
								c.sendAlert(alertInternalError)
								return errors.New("crypto/tls: private key unexpectedly of wrong type")
							}

							ss, err := kem.Decapsulate(sk, hs.clientHello.ciphertextKEMTLS)
							if err != nil {
								return err
							}
							hs.pdkKEMTLS = true
							hs.ssKEMTLS = ss
							hs.hello.pdkKEMTLS = true
						}
					}
				}			
			} else {								
				
				certMsg := new(certificateMsgTLS13)

				certMsg.certificate = *hs.cert
				certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
				certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
				certMsg.delegatedCredential = hs.clientHello.delegatedCredentialSupported && len(hs.cert.DelegatedCredential) > 0

				certMsgRaw := certMsg.marshal()
				cachedCertHash := calculateHashCachedInfo(certMsgRaw)
				
				if bytes.Equal(cachedCertHash, hs.clientHello.cachedInformationCertHash) {
					hs.hello.cachedInformationCert = true					
	
					sk, ok1 := hs.cert.PrivateKey.(*kem.PrivateKey)
					if !ok1 {
						c.sendAlert(alertInternalError)
						return errors.New("crypto/tls: private key unexpectedly of wrong type")
					}

					ss, err := kem.Decapsulate(sk, hs.clientHello.ciphertextKEMTLS)
					if err != nil {
						return err
					}
					hs.pdkKEMTLS = true
					hs.ssKEMTLS = ss
					hs.hello.pdkKEMTLS = true
				}				
			}
		} else {
			certMsg := new(certificateMsgTLS13)

			certMsg.certificate = *hs.cert
			certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
			certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
			certMsg.delegatedCredential = hs.clientHello.delegatedCredentialSupported && len(hs.cert.DelegatedCredential) > 0

			certMsgRaw := certMsg.marshal()
			cachedCertHash := calculateHashCachedInfo(certMsgRaw)
			
			if bytes.Equal(cachedCertHash, hs.clientHello.cachedInformationCertHash) {
				hs.hello.cachedInformationCert = true
				hs.certHash = cachedCertHash
				
				hs.usingCachedInformation = true				
			}				
		}
	}

	if hs.clientHello.cachedInformationCertReq {
		cachedCertReqHash := calculateHashCachedInfo(c.config.CachedCertReq)
		if bytes.Equal(cachedCertReqHash, hs.clientHello.cachedInformationCertReqHash) {
			hs.hello.cachedInformationCertReq = true
		}
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if hs.clientHello.echIsInner {
		// If confirming ECH acceptance, then clear the last 8 bytes of the
		// ServerHello.random in preparation for computing the confirmation
		// hint.
		copy(hs.hello.random[24:], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	if hs.clientHello.earlyData {
		// See RFC 8446, Section 4.2.10 for the complicated behavior required
		// here. The scenario is that a different server at our address offered
		// to accept early data in the past, which we can't handle. For now, all
		// 0-RTT enabled session tickets need to expire before a Go server can
		// replace a server or join a pool. That's the same requirement that
		// applies to mixing or replacing with any TLS 1.2 server.
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: client sent unexpected early data")
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = defaultCipherSuitesTLS13()
		supportedList = hs.clientHello.cipherSuites

		// If the client does not seem to have hardware support for AES-GCM,
		// prefer other AEAD ciphers even if we prioritized AES-GCM ciphers
		// by default.
		if !aesgcmPreferred(hs.clientHello.cipherSuites) {
			preferenceList = deprioritizeAES(preferenceList)
		}
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = defaultCipherSuitesTLS13()

		// If we don't have hardware support for AES-GCM, prefer other AEAD
		// ciphers even if the client prioritized AES-GCM.
		if !hasAESGCMHardwareSupport {
			preferenceList = deprioritizeAES(preferenceList)
		}
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(supportedList, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	hs.transcript = hs.suite.hash.New()

	// Resolve the server's preference for the ECDHE group.
	supportedCurves := c.config.curvePreferences()
	if testingTriggerHRR {
		// A HelloRetryRequest (HRR) is sent if the client does not offer a key
		// share for a curve supported by the server. To trigger this condition
		// intentionally, we compute the set of ECDHE groups supported by both
		// the client and server but for which the client did not offer a key
		// share.
		m := make(map[CurveID]bool)
		for _, serverGroup := range c.config.curvePreferences() {
			for _, clientGroup := range hs.clientHello.supportedCurves {
				if clientGroup == serverGroup {
					m[clientGroup] = true
				}
			}
		}
		for _, ks := range hs.clientHello.keyShares {
			delete(m, ks.group)
		}
		supportedCurves = nil
		for group := range m {
			supportedCurves = append(supportedCurves, group)
		}
		if len(supportedCurves) == 0 {
			// This occurs if the client offered a key share for each mutually
			// supported group.
			panic("failed to trigger HelloRetryRequest")
		}
	}

	// Pick the ECDHE group in server preference order, but give priority to
	// groups with a key share, to avoid a HelloRetryRequest round-trip.
	var selectedGroup CurveID
	var clientKeyShare *keyShare

GroupSelection:
	for _, preferredGroup := range supportedCurves {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == preferredGroup {
				selectedGroup = ks.group
				clientKeyShare = &ks
				break GroupSelection
			}
		}
		if selectedGroup != 0 {
			continue
		}
		for _, group := range hs.clientHello.supportedCurves {
			if group == preferredGroup {
				selectedGroup = group
				break
			}
		}
	}
	if selectedGroup == 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no ECDHE curve supported by both client and server")
	}
	if clientKeyShare == nil {
		if err := hs.doHelloRetryRequest(selectedGroup); err != nil {
			return err
		}
		clientKeyShare = &hs.clientHello.keyShares[0]
	}

	if selectedGroup.isKEM() && (c.config.KEMTLSEnabled || c.config.PQTLSEnabled) {
		sharedKey, ciphertext, err := kem.Encapsulate(c.config.rand(), &kem.PublicKey{KEMId: kem.ID(selectedGroup), PublicKey: clientKeyShare.data})
		if err != nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: CurvePreferences includes unsupported curve")
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: ciphertext}
		hs.sharedKey = sharedKey
		hs.keyKEMShare = true
		// Secret Print
		// fmt.Printf("Server KEX\nKEMId: %x\nsharedKey:\n  %x\n\n", kem.ID(selectedGroup), sharedKey)
	} else {
		if _, ok := curveForCurveID(selectedGroup); (selectedGroup != X25519 && !selectedGroup.isKEM()) && !ok {
			c.sendAlert(alertInternalError)
			return errors.New("tls: CurvePreferences includes unsupported curve")
		}
		params, err := generateECDHEParameters(c.config.rand(), selectedGroup)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: params.PublicKey()}
		hs.sharedKey = params.SharedKey(clientKeyShare.data)
	}

	if hs.sharedKey == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid client key share")
	}

	c.serverName = hs.clientHello.serverName

	hs.handshakeTimings.ProcessClientHello = hs.handshakeTimings.elapsedTime()

	return nil
}

func (hs *serverHandshakeStateTLS13) checkForResumption() error {
	c := hs.c

	if c.config.SessionTicketsDisabled || c.config.ECHEnabled {
		return nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid or missing PSK binders")
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil
	}

	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}

		plaintext, _ := c.decryptTicket(identity.label)
		if plaintext == nil {
			continue
		}
		sessionState := new(sessionStateTLS13)
		if ok := sessionState.unmarshal(plaintext); !ok {
			continue
		}

		createdAt := time.Unix(int64(sessionState.createdAt), 0)
		if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
			continue
		}

		// We don't check the obfuscated ticket age because it's affected by
		// clock skew and it's only a freshness signal useful for shrinking the
		// window for replay attacks, which don't affect us as we don't do 0-RTT.

		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.certificate.Certificate) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}

		psk := hs.suite.expandLabel(sessionState.resumptionSecret, "resumption",
			nil, hs.suite.hash.Size())
		hs.earlySecret = hs.suite.extract(psk, nil)
		binderKey := hs.suite.deriveSecret(hs.earlySecret, resumptionBinderLabel, nil)
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: internal error: failed to clone hash")
		}
		transcript.Write(hs.clientHello.marshalWithoutBinders())
		pskBinder := hs.suite.finishedHash(binderKey, transcript)
		if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
			c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid PSK binder")
		}

		c.didResume = true
		if err := c.processCertsFromClient(sessionState.certificate); err != nil {
			return err
		}

		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		hs.usingPSK = true
		return nil
	}

	return nil
}

// cloneHash uses the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
// interfaces implemented by standard library hashes to clone the state of in
// to a new instance of h. It returns nil if the operation fails.
func cloneHash(in hash.Hash, h crypto.Hash) hash.Hash {
	// Recreate the interface to avoid importing encoding.
	type binaryMarshaler interface {
		MarshalBinary() (data []byte, err error)
		UnmarshalBinary(data []byte) error
	}
	marshaler, ok := in.(binaryMarshaler)
	if !ok {
		return nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil
	}
	out := h.New()
	unmarshaler, ok := out.(binaryMarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil
	}
	return out
}

// getDelegatedCredential will return a Delegated Credential pair (a Delegated
// Credential and its private key) for the given ClientHelloInfo, defaulting to
// the first element of cert.DelegatedCredentialPair.
// The returned Delegated Credential could be invalid for usage in the handshake.
// Returns an error if there are no delegated credentials or if the one found
// cannot be used for the current connection.
func getDelegatedCredential(clientHello *ClientHelloInfo, cert *Certificate) (*DelegatedCredentialPair, error) {
	if len(cert.DelegatedCredentials) == 0 {
		return nil, errors.New("No Delegated Credential found.")
	}

	if len(cert.DelegatedCredentials) == 1 {
		// There's only one choice, so no point doing any work.
		return &cert.DelegatedCredentials[0], nil
	}

	for _, dcPair := range cert.DelegatedCredentials {
		// The client must have sent the signature_algorithms in the DC extension: ensure it supports
		// schemes we can use with this delegated credential.
		if len(clientHello.SignatureSchemesDC) > 0 {
			if _, err := selectSignatureSchemeDC(VersionTLS13, dcPair.DC, clientHello.SignatureSchemesDC); err == nil {
				return &dcPair, nil
			}
		}
	}

	// No delegated credential can be returned.
	return nil, errors.New("No valid Delegated Credential found.")
}

func (hs *serverHandshakeStateTLS13) pickCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if hs.pdkKEMTLS && hs.keyKEMShare {
		return nil
	}

	if hs.usingCachedInformation {
		c.didPQTLS = true
		return nil
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert(alertMissingExtension)
	}

	var certificate *Certificate	
	var err error

	if c.config.WrappedCertEnabled && (len(hs.clientHello.certPSK.identities) > 0) {
		certificate = new(Certificate)

		encodedIdentity := hex.EncodeToString(hs.clientHello.certPSK.identities[0])
		// JP: TODO: How to proceed when the client send multiple identities		
		*certificate = hs.WrappedCertsDB[encodedIdentity]
	} else {
		certificate, err = c.config.getCertificate(clientHelloInfo(c, hs.clientHello))
		if err != nil {
			if err == errNoCertificates {
				c.sendAlert(alertUnrecognizedName)
			} else {
				c.sendAlert(alertInternalError)
			}
			return err
		}
	}

	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	hs.cert = certificate

	if hs.clientHello.delegatedCredentialSupported && len(hs.clientHello.supportedSignatureAlgorithmsDC) > 0 {
		delegatedCredentialPair, err := getDelegatedCredential(clientHelloInfo(c, hs.clientHello), hs.cert)
		if err != nil {
			// a Delegated Credential was not found. Fallback to the certificate.
			return nil
		}

		if delegatedCredentialPair.DC != nil && delegatedCredentialPair.PrivateKey != nil {
			// Even if the Delegated Credential has already been marshalled, be sure it is the correct one.
			delegatedCredentialPair.DC.raw, err = delegatedCredentialPair.DC.marshal()
			if err != nil {
				// invalid Delegated Credential. Fallback to the certificate.
				return nil
			}

			hs.sigAlg, err = selectSignatureSchemeDC(c.vers, delegatedCredentialPair.DC, hs.clientHello.supportedSignatureAlgorithmsDC)
			if err != nil {
				// the Delegated Credential is unsupported or
				// incompatible with the client's signature algorithms.
				// Fallback to the certificate.
				return nil
			}

			hs.cert.DelegatedCredentialPrivateKey = delegatedCredentialPair.PrivateKey
			hs.cert.DelegatedCredential = delegatedCredentialPair.DC.raw
			if hs.keyKEMShare {
				if delegatedCredentialPair.DC.cred.expCertVerfAlgo.isKEMTLS() {
					hs.isKEMTLS = true
				} else if delegatedCredentialPair.DC.cred.expCertVerfAlgo.isPQTLS() {
					c.didPQTLS = true
				} else {
					return nil
				}
			}
		}
	} else {
		if hs.keyKEMShare {
			if hs.sigAlg.isKEMTLS() {
				hs.isKEMTLS = true
			} else if hs.sigAlg.isPQTLS() {
				c.didPQTLS = true
			} else {
				c.sendAlert(alertHandshakeFailure)
				return err
			}
		}
	}

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	return err
}

func (hs *serverHandshakeStateTLS13) doHelloRetryRequest(selectedGroup CurveID) error {
	c := hs.c
	c.hrrTriggered = true

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	hs.transcript.Write(hs.clientHello.marshal())
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)

	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom,
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
	}

	hs.transcript.Write(helloRetryRequest.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, helloRetryRequest.marshal()); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientHello, msg)
	}

	clientHello, err = c.echAcceptOrReject(clientHello)
	if err != nil {
		return fmt.Errorf("tls: %s", err) // Alert sent
	}

	if len(clientHello.keyShares) != 1 || clientHello.keyShares[0].group != selectedGroup {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client sent invalid key share in second ClientHello")
	}

	if clientHello.earlyData {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client indicated early data in second ClientHello")
	}

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client illegally modified second ClientHello")
	}

	hs.clientHello = clientHello
	return nil
}

// illegalClientHelloChange reports whether the two ClientHello messages are
// different, with the exception of the changes allowed before and after a
// HelloRetryRequest. See RFC 8446, Section 4.1.2.
func illegalClientHelloChange(ch, ch1 *clientHelloMsg) bool {
	if len(ch.supportedVersions) != len(ch1.supportedVersions) ||
		len(ch.cipherSuites) != len(ch1.cipherSuites) ||
		len(ch.supportedCurves) != len(ch1.supportedCurves) ||
		len(ch.supportedSignatureAlgorithms) != len(ch1.supportedSignatureAlgorithms) ||
		len(ch.supportedSignatureAlgorithmsCert) != len(ch1.supportedSignatureAlgorithmsCert) ||
		len(ch.supportedSignatureAlgorithmsDC) != len(ch1.supportedSignatureAlgorithmsDC) ||
		len(ch.alpnProtocols) != len(ch1.alpnProtocols) {
		return true
	}
	for i := range ch.supportedVersions {
		if ch.supportedVersions[i] != ch1.supportedVersions[i] {
			return true
		}
	}
	for i := range ch.cipherSuites {
		if ch.cipherSuites[i] != ch1.cipherSuites[i] {
			return true
		}
	}
	for i := range ch.supportedCurves {
		if ch.supportedCurves[i] != ch1.supportedCurves[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithms {
		if ch.supportedSignatureAlgorithms[i] != ch1.supportedSignatureAlgorithms[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsCert {
		if ch.supportedSignatureAlgorithmsCert[i] != ch1.supportedSignatureAlgorithmsCert[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsDC {
		if ch.supportedSignatureAlgorithmsDC[i] != ch1.supportedSignatureAlgorithmsDC[i] {
			return true
		}
	}
	for i := range ch.alpnProtocols {
		if ch.alpnProtocols[i] != ch1.alpnProtocols[i] {
			return true
		}
	}
	return ch.vers != ch1.vers ||
		!bytes.Equal(ch.random, ch1.random) ||
		!bytes.Equal(ch.sessionId, ch1.sessionId) ||
		!bytes.Equal(ch.compressionMethods, ch1.compressionMethods) ||
		ch.serverName != ch1.serverName ||
		ch.ocspStapling != ch1.ocspStapling ||
		!bytes.Equal(ch.supportedPoints, ch1.supportedPoints) ||
		ch.ticketSupported != ch1.ticketSupported ||
		!bytes.Equal(ch.sessionTicket, ch1.sessionTicket) ||
		ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported ||
		!bytes.Equal(ch.secureRenegotiation, ch1.secureRenegotiation) ||
		ch.delegatedCredentialSupported != ch1.delegatedCredentialSupported ||
		ch.scts != ch1.scts ||
		!bytes.Equal(ch.cookie, ch1.cookie) ||
		!bytes.Equal(ch.pskModes, ch1.pskModes)
}

func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = hs.suite.extract(nil, nil)
	}
	hs.handshakeSecret = hs.suite.extract(hs.sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	// Confirm ECH acceptance.
	if hs.clientHello.echIsInner {
		confTranscript := cloneHash(hs.transcript, hs.suite.hash)
		if confTranscript == nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: internal error: failed to clone hash")
		}
		confTranscript.Write(hs.clientHello.marshal())
		confTranscript.Write(hs.hello.marshal())
		conf := hs.suite.deriveSecret(hs.handshakeSecret,
			echAcceptConfirmationLabel, confTranscript)
		copy(hs.hello.random[24:], conf[:8])
		hs.hello.raw = nil
	}

	marshalledServerHello := hs.hello.marshal()

	hs.transcript.Write(hs.clientHello.marshal())
	hs.transcript.Write(marshalledServerHello)
	if _, err := c.writeRecord(recordTypeHandshake, marshalledServerHello); err != nil {
		return err
	}

	hs.handshakeTimings.WriteServerHello = hs.handshakeTimings.elapsedTime()

	serverHelloSize, err1 := getMessageLength(marshalledServerHello)
	if err1 != nil {
		return err1
	}

	hs.c.serverHandshakeSizes.ServerHello = serverHelloSize

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	clientSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, clientSecret)
	serverSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)

	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); selectedProto != "" {
			encryptedExtensions.alpnProtocol = selectedProto
			c.clientProtocol = selectedProto
		}
	}

	if !c.ech.accepted && len(c.ech.retryConfigs) > 0 {
		encryptedExtensions.ech = c.ech.retryConfigs
	}

	marshalledEE := encryptedExtensions.marshal()

	hs.transcript.Write(marshalledEE)
	if _, err := c.writeRecord(recordTypeHandshake, marshalledEE); err != nil {
		return err
	}

	hs.handshakeTimings.WriteEncryptedExtensions = hs.handshakeTimings.elapsedTime()

	eeSize, err := getMessageLength(marshalledEE)
	if err != nil {
		return err
	}

	hs.c.serverHandshakeSizes.EncryptedExtensions = eeSize

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if hs.pdkKEMTLS && hs.keyKEMShare {
		hs.isKEMTLS = true
		return nil
	}

	if hs.requestClientCert() || hs.requestClientKEMCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportDelegatedCredential = c.config.SupportDelegatedCredential
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		certReq.supportedSignatureAlgorithmsDC = supportedSignatureAlgorithmsDC
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		hs.certReq = certReq

		marshalledCertReq := certReq.marshal()
		hs.transcript.Write(marshalledCertReq)
		if _, err := c.writeRecord(recordTypeHandshake, marshalledCertReq); err != nil {
			return err
		}

		c.certificateReqMessage = marshalledCertReq

		certReqSize, err := getMessageLength(marshalledCertReq)
		if err != nil {
			return err
		}
	
		hs.c.serverHandshakeSizes.CertificateRequest = certReqSize
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
	certMsg.delegatedCredential = hs.clientHello.delegatedCredentialSupported && len(hs.cert.DelegatedCredential) > 0

	c.certificateMessage = certMsg.marshal()

	if hs.usingCachedInformation && hs.certHash != nil {
		cachedCertMsg := new(certificateMsgTLS13CachedInfo)
		cachedCertMsg.hash_value = hs.certHash 

		marshalledCachedCert := cachedCertMsg.marshal()
		
		hs.transcript.Write(marshalledCachedCert)
		if _, err := c.writeRecord(recordTypeHandshake, marshalledCachedCert); err != nil {
			return err
		}
	
		hs.handshakeTimings.WriteCertificate = hs.handshakeTimings.elapsedTime()
		
		cachedCertLength, err := getMessageLength(marshalledCachedCert)
		if err != nil {
			return err
		}

		hs.c.serverHandshakeSizes.Certificate = cachedCertLength
	} else {
		
		marshalledCertificate := certMsg.marshal()
		hs.transcript.Write(marshalledCertificate)
		if _, err := c.writeRecord(recordTypeHandshake, marshalledCertificate); err != nil {
			return err
		}

		hs.handshakeTimings.WriteCertificate = hs.handshakeTimings.elapsedTime()

		certificateLength, err := getMessageLength(marshalledCertificate)
		if err != nil {
			return err
		}

		hs.c.serverHandshakeSizes.Certificate = certificateLength
	}


	if !hs.isKEMTLS {
		certVerifyMsg := new(certificateVerifyMsg)
		certVerifyMsg.hasSignatureAlgorithm = true
		certVerifyMsg.signatureAlgorithm = hs.sigAlg

		sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
		if err != nil {
			return c.sendAlert(alertInternalError)
		}

		signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}

		var sig []byte
		if len(hs.cert.DelegatedCredential) > 0 {
			var err error
			sig, err = hs.cert.DelegatedCredentialPrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
			if err != nil {
				public := hs.cert.DelegatedCredentialPrivateKey.(crypto.Signer).Public()
				if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
					rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
					c.sendAlert(alertHandshakeFailure)
				} else {
					c.sendAlert(alertInternalError)
				}
				return errors.New("tls: failed to sign handshake: " + err.Error())
			}
		} else {
			var err error
			sig, err = hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
			if err != nil {
				public := hs.cert.PrivateKey.(crypto.Signer).Public()
				if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
					rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
					c.sendAlert(alertHandshakeFailure)
				} else {
					c.sendAlert(alertInternalError)
				}
				return errors.New("tls: failed to sign handshake: " + err.Error())
			}
		}
		certVerifyMsg.signature = sig

		marshalledCertVerify := certVerifyMsg.marshal()

		hs.transcript.Write(marshalledCertVerify)
		if _, err := c.writeRecord(recordTypeHandshake, marshalledCertVerify); err != nil {
			return err
		}

		hs.handshakeTimings.WriteCertificateVerify = hs.handshakeTimings.elapsedTime()

		certVerifyLength, err := getMessageLength(marshalledCertVerify)		
		if err != nil {
			return err
		}

		hs.c.serverHandshakeSizes.CertificateVerify = certVerifyLength
	} else {
		hs.handshakeTimings.WriteCertificateVerify = hs.handshakeTimings.elapsedTime()
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	if hs.isKEMTLS == true {
		return nil
	}

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	marshalledFinished := finished.marshal()

	hs.transcript.Write(marshalledFinished)
	if _, err := c.writeRecord(recordTypeHandshake, marshalledFinished); err != nil {
		return err
	}

	hs.handshakeTimings.WriteServerFinished = hs.handshakeTimings.elapsedTime()

	finishedSize, err1 := getMessageLength(marshalledFinished)
	if err1 != nil {
		return err1
	}

	hs.c.serverHandshakeSizes.Finished = finishedSize

	// Derive secrets that take context through the server Finished.

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))

	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}

		// If wrapped cert is enabled and the client is willing to establish a new PSK
		// then create a new Cert PSK and send it
		if c.config.WrappedCertEnabled && hs.clientHello.certPSK.establishPSK {
			if err := hs.sendCertPSK(); err != nil {
				return err
			}
		}		
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled || hs.c.config.ECHEnabled {
		return false
	}

	// Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
	for _, pskMode := range hs.clientHello.pskModes {
		if pskMode == pskModeDHE {
			return true
		}
	}
	return false
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	hs.transcript.Write(finishedMsg.marshal())

	if !hs.shouldSendSessionTickets() {
		return nil
	}

	resumptionSecret := hs.suite.deriveSecret(hs.masterSecret,
		resumptionLabel, hs.transcript)

	m := new(newSessionTicketMsgTLS13)

	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	state := sessionStateTLS13{
		cipherSuite:      hs.suite.id,
		createdAt:        uint64(c.config.time().Unix()),
		resumptionSecret: resumptionSecret,
		certificate: Certificate{
			Certificate:                 certsFromClient,
			OCSPStaple:                  c.ocspResponse,
			SignedCertificateTimestamps: c.scts,
		},
	}
	var err error
	m.label, err = c.encryptTicket(state.marshal())
	if err != nil {
		return err
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)

	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendCertPSK() error {
	c := hs.c

	if hs.clientFinished == nil {  // It could be already computed by sendSessionTickets
		hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
		
		finishedMsg := &finishedMsg{
			verifyData: hs.clientFinished,
		}
		
		hs.transcript.Write(finishedMsg.marshal())
	}
	
	resumptionSecret := hs.suite.deriveSecret(hs.masterSecret,
		resumptionLabel, hs.transcript)

	m := new(newCertPSKMsgTLS13)
	
	/* --------------------------------- Início --------------------------------- */

	// Este trecho de código é necessário para geração do state, que será 
	// cifrado e usado como label/identidade da PSK. Foi feito desta forma
	// com a intenção de imitar o que é feito no PSK do TLS


	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	
	
	state := sessionStateTLS13{
		cipherSuite:      hs.suite.id,
		createdAt:        uint64(c.config.time().Unix()),
		resumptionSecret: resumptionSecret,
		certificate: Certificate{
			Certificate:                 certsFromClient,
			OCSPStaple:                  c.ocspResponse,
			SignedCertificateTimestamps: c.scts,
		},
	}

	cipherSuite := cipherSuiteTLS13ByID(hs.suite.id)
	if cipherSuite == nil {
		return errors.New("wrapped cert: unknown ciphersuit")
	}

	/* ----------------------------------- Fim ---------------------------------- */	
		
	var err error

	m.label, err = c.encryptTicket(state.marshal())  // Atribuindo o label da PSK
	if err != nil {
		return err
	}

	m.nonce = make([]byte, 32)  // Qual deve ser o tamanho do nonce...?

	if _, err := rand.Read(m.nonce); err != nil {
		panic("wrapped cert: nonce generation failed: " + err.Error())
	}
	

	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}

	certPSKMasterSecret := hs.suite.deriveSecret(hs.masterSecret,
		wrappedCertLabel, hs.transcript)

	psk := cipherSuite.expandLabel(certPSKMasterSecret, "cert psk",
		m.nonce, cipherSuite.hash.Size())

	c.conn.RemoteAddr().String()

	// dbKey will be the client's IP address	
	if err := certPSKWriteToFile(c.conn.RemoteAddr().String(), m.label, psk, false); err != nil {
		return err
	}

	fmt.Printf("Label:\n%x\n\n", m.label)
	fmt.Printf("Nonce:\n%x\n\n", m.nonce)
	fmt.Printf("PSK:\n%x\n\n", psk)

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientCertificate() error {
	c := hs.c

	if hs.isKEMTLS == true {
		return nil
	}

	if !hs.requestClientCert() {
		// Make sure the connection is still being verified whether or not
		// the server requested a client certificate.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// If we requested a client certificate, then the client must send a
	// certificate message. If it's empty, no CertificateVerify is sent.

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.transcript.Write(certMsg.marshal())

	if err := c.processCertsFromClient(certMsg.certificate); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	hs.handshakeTimings.ReadCertificate = hs.handshakeTimings.elapsedTime()

	if len(certMsg.certificate.Certificate) != 0 {
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}

		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// See RFC 8446, Section 4.4.3.
		if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: client certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
		if err != nil {
			return c.sendAlert(alertInternalError)
		}
		if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: client certificate used with invalid signature algorithm")
		}

		if certMsg.delegatedCredential {
			if err := hs.processDelegatedCredentialFromClient(certMsg.certificate.DelegatedCredential, certVerify); err != nil {
				return err
			}
		}

		pk := c.peerCertificates[0].PublicKey
		if c.verifiedDC != nil {
			pk = c.verifiedDC.cred.publicKey
		}

		signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
		if err := verifyHandshakeSignature(sigType, pk, sigHash, signed, certVerify.signature); err != nil {
			c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid signature by the client certificate: " + err.Error())
		}

		hs.transcript.Write(certVerify.marshal())

		c.didClientAuthentication = true
	}

	hs.handshakeTimings.ReadCertificateVerify = hs.handshakeTimings.elapsedTime()

	// If we waited until the client certificates to send session tickets, we
	// are ready to do it now.
	if err := hs.sendSessionTickets(); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientFinished() error {
	c := hs.c

	if hs.isKEMTLS == true {
		return nil
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid client finished hash")
	}

	hs.handshakeTimings.ReadClientFinished = hs.handshakeTimings.elapsedTime()

	c.in.setTrafficSecret(hs.suite, hs.trafficSecret)

	return nil
}


func (hs *serverHandshakeStateTLS13) loadAllWrappedCerts() error {
	
	wrappedCertsDir := hs.c.config.WrappedCertsDir
	serverDomain := "teste"

	file, err := os.Open(wrappedCertsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	defer file.Close()

	list, err := file.Readdirnames(0) // 0 to read all files and folders
	if err != nil {
		return err
	}

	for _, dirName := range list {
		loadedCert, err := LoadX509KeyPair(filepath.Join(wrappedCertsDir, dirName, serverDomain+".crt"), filepath.Join(wrappedCertsDir, dirName, serverDomain+".key"))
		if err != nil {
			return err
		}

		hs.WrappedCertsDB[dirName] = loadedCert		
	}

	return nil
}
