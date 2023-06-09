<img src=".etc/icon.png" align="right" height="300" width="300"/>

# CIRCL

[![CIRCL](https://circl/workflows/CIRCL/badge.svg)](https://circl/actions)
[![GoDoc](https://godoc.org/circl?status.svg)](https://pkg.go.dev/circl?tab=overview)
[![Go Report Card](https://goreportcard.com/badge/circl)](https://goreportcard.com/report/circl)
[![codecov](https://codecov.io/gh/cloudflare/circl/branch/master/graph/badge.svg)](https://codecov.io/gh/cloudflare/circl)

**CIRCL** (Cloudflare Interoperable, Reusable Cryptographic Library) is a collection
of cryptographic primitives written in Go. The goal of this library is to be used as a tool for
experimental deployment of cryptographic algorithms targeting Post-Quantum (PQ) and Elliptic
Curve Cryptography (ECC).

## Security Disclaimer

🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental.

## Installation

You can get it by typing:

```sh
go get -u circl
```

## Versioning

Version numbers are [Semvers](https://semver.org/). We release a minor version for new functionality, a major version for breaking API changes, and increment the patchlevel for bugfixes.

## Implemented Primitives

| Category | Algorithms | Description | Applications |
|-----------|------------|-------------|--------------|
| PQ Key Exchange | SIDH | SIDH provide key exchange mechanisms using ephemeral keys. | Post-quantum key exchange in TLS |
| PQ Key Exchange | cSIDH | Isogeny based drop-in replacement for Diffie–Hellman | Post-Quantum Key exchange. |
| PQ KEM | SIKE | SIKE is a key encapsulation mechanism (KEM). | Post-quantum key exchange in TLS |
| Key Exchange | X25519, X448 | RFC-7748 provides new key exchange mechanisms based on Montgomery elliptic curves. | TLS 1.3. Secure Shell. |
| Key Exchange | FourQ | One of the fastest elliptic curves at 128-bit security level. | Experimental for key agreement and digital signatures. |
| Key Exchange / Digital signatures | P-384 | Our optimizations reduce the burden when moving from P-256 to P-384. |  ECDSA and ECDH using Suite B at top secret level. |
| Digital Signatures | Ed25519, Ed448 | RFC-8032 provides new signature schemes based on Edwards curves. | Digital certificates and authentication. |
| Key Encapsulation | P-256, P-384, P-521, X25519 and X448 | Key encapsulation methods based on Diffie-Hellman. | HPKE |
| Hybrid Public-Key Encryption | Base, Auth, PSK, AuthPSK | [HPKE](https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-07.html) is a combination of KEM and AEAD. | TLS |
| PQ KEM/PKE | Kyber | Lattice (M-LWE) based IND-CCA2 secure key encapsulation mechanism and IND-CPA secure public key encryption  | Post-Quantum Key exchange |
| PQ Digital Signatures | Dilithium, Hybrid modes | Lattice (Module LWE) based signature scheme | Post-Quantum PKI |

### Work in Progress

| Category | Algorithms | Description | Applications |
|----------|------------|-------------|--------------|
| Hashing to Elliptic Curve Groups | Several algorithms: Elligator2, Ristretto, SWU, Icart. | Protocols based on elliptic curves require hash functions that map bit strings to points on an elliptic curve.  | VOPRF. OPAQUE. PAKE. Verifiable random functions. |
| Bilinear Pairings | Plans for moving BN256 to stronger pairing curves. | A bilineal pairing is a mathematical operation that enables the implementation of advanced cryptographic protocols, such as identity-based encryption (IBE), short digital signatures (BLS), and attribute-based encryption (ABE). | Geo Key Manager, Randomness Beacon, Ethereum and other blockchain applications. |
| PQ KEM | HRSS-SXY | Lattice (NTRU) based key encapsulation mechanism. | Key exchange for low-latency environments |
| PQ Digital Signatures | SPHINCS+ | Stateless hash-based signature scheme | Post-Quantum PKI |

## Testing and Benchmarking

Library comes with number of make targets which can be used for testing and
benchmarking:

- ``test`` performs testing of the binary.
- ``bench`` runs benchmarks.
- ``cover`` produces coverage.
- ``lint`` runs set of linters on the code base.

## Contributing

To contribute, fork this repository and make your changes, and then make a Pull
Request. A Pull Request requires approval of the admin team and a successful
CI build.

## How to Cite 

To cite CIRCL, use one of the following formats and update with the date
you accessed this project.

APA Style

```
Faz-Hernández, A. and Kwiatkowski, K. (2019). Introducing CIRCL: 
An Advanced Cryptographic Library. Cloudflare. Available at 
https://circl. Accessed Feb 2021.
```

Bibtex Source

```bibtex
@manual{circl,
  title        = {Introducing CIRCL: An Advanced Cryptographic Library},
  author       = {Armando Faz-Hern\'{a}ndez and Kris Kwiatkowski},
  organization = {Cloudflare},
  abstract     = {{CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library) is
                   a collection of cryptographic primitives written in Go. The goal 
                   of this library is to be used as a tool for experimental 
                   deployment of cryptographic algorithms targeting Post-Quantum (PQ)
                   and Elliptic Curve Cryptography (ECC).}},
  note         = {Available at \url{https://circl}. Accessed Feb 2021},
  month        = jun,
  year         = {2019}
}
```

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
