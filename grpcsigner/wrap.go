package grpcsigner

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/tg123/remotesigner"
)

type wrapinst struct {
	grpc SignerClient
}

var _ remotesigner.RemoteSigner = (*wrapinst)(nil)

func New(client SignerClient) remotesigner.RemoteSigner {
	return &wrapinst{client}
}

func (g *wrapinst) Sign(ctx context.Context, digest []byte, algo remotesigner.SignerAlgorithm) ([]byte, error) {
	reply, err := g.grpc.Sign(ctx, &SignRequest{
		Digest:    digest,
		Algorithm: string(algo),
	})

	if err != nil {
		return nil, err
	}

	return reply.Signature, nil
}

func (g *wrapinst) Public() crypto.PublicKey {
	reply, err := g.grpc.PublicKey(context.Background(), &PublicKeyRequest{})

	if err != nil {
		return nil
	}

	switch reply.Type {
	case "PKIX":
		p, err := x509.ParsePKIXPublicKey(reply.Data)
		if err != nil {
			return nil
		}

		return p
	case "PKCS1":
		p, err := x509.ParsePKCS1PublicKey(reply.Data)
		if err != nil {
			return nil
		}
		return p
	}

	return nil
}
