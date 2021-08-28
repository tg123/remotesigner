package remotesigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
)

type SignerAlgorithm string

const (
	SignerAlgorithmRsaPss256 SignerAlgorithm = "RSASSA_PSS_SHA_256"
	SignerAlgorithmRsaPss384 SignerAlgorithm = "RSASSA_PSS_SHA_384"
	SignerAlgorithmRsaPss512 SignerAlgorithm = "RSASSA_PSS_SHA_512"

	SignerAlgorithmRsaPkcs256 SignerAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	SignerAlgorithmRsaPkcs384 SignerAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	SignerAlgorithmRsaPkcs512 SignerAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"

	SignerAlgorithmEcdsa256 SignerAlgorithm = "ECDSA_SHA_256"
	SignerAlgorithmEcdsa384 SignerAlgorithm = "ECDSA_SHA_384"
	SignerAlgorithmEcdsa512 SignerAlgorithm = "ECDSA_SHA_512"
)

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = fmt.Errorf("unsupported hash algorithm")
)

type SignerOpts struct {
	Algorithm SignerAlgorithm
	Context   context.Context
}

func (o *SignerOpts) HashFunc() crypto.Hash {
	switch o.Algorithm {
	case SignerAlgorithmRsaPss256, SignerAlgorithmRsaPkcs256, SignerAlgorithmEcdsa256:
		return crypto.SHA256
	case SignerAlgorithmRsaPss384, SignerAlgorithmRsaPkcs384, SignerAlgorithmEcdsa384:
		return crypto.SHA384
	case SignerAlgorithmRsaPss512, SignerAlgorithmRsaPkcs512, SignerAlgorithmEcdsa512:
		return crypto.SHA512
	}
	return 0
}

type RemoteSigner interface {
	Sign(ctx context.Context, digest []byte, algo SignerAlgorithm) ([]byte, error)
	Public() crypto.PublicKey
}

type inst struct {
	impl RemoteSigner
}

func New(remote RemoteSigner) crypto.Signer {
	return &inst{
		impl: remote,
	}
}

func (v *inst) Public() crypto.PublicKey {
	return v.impl.Public()
}

func (v *inst) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("bad digest for hash")
	}

	var algo SignerAlgorithm
	var ctx context.Context

	switch opt := opts.(type) {
	case *SignerOpts:
		algo = opt.Algorithm
		ctx = opt.Context
	case *rsa.PSSOptions:
		switch hash {
		case crypto.SHA256:
			algo = SignerAlgorithmRsaPss256
		case crypto.SHA384:
			algo = SignerAlgorithmRsaPss384
		case crypto.SHA512:
			algo = SignerAlgorithmRsaPss512
		default:
			return nil, ErrUnsupportedHash
		}

	default:
		switch hash {
		case crypto.SHA256:
			algo = SignerAlgorithmRsaPkcs256
		case crypto.SHA384:
			algo = SignerAlgorithmRsaPkcs384
		case crypto.SHA512:
			algo = SignerAlgorithmRsaPkcs512
		default:
			return nil, ErrUnsupportedHash
		}
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return v.impl.Sign(ctx, digest, algo)
}
