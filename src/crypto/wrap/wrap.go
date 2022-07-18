package wrap

import "crypto/elliptic"

type PublicKey struct {
	ClassicAlgorithm  elliptic.Curve
	WrappedPk []byte
}