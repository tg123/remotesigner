package grpcsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

type server struct {
	UnimplementedSignerServer
	signer crypto.Signer
}

func NewSignerServer(signer crypto.Signer) SignerServer {
	return &server{signer: signer}
}

func (s *server) Sign(_ context.Context, req *SignRequest) (*SignReply, error) {
	sig, err := s.signer.Sign(rand.Reader, req.Digest, &remotesigner.SignerOpts{
		Algorithm: remotesigner.SignerAlgorithm(req.Algorithm),
	})

	if err != nil {
		return nil, err
	}

	return &SignReply{
		Signature: sig,
	}, nil
}

func (s *server) PublicKey(_ context.Context, _ *PublicKeyRequest) (*PublicKeyReply, error) {
	p := s.signer.Public()

	k, ok := p.(*rsa.PublicKey)

	if ok {
		return &PublicKeyReply{
			Data: x509.MarshalPKCS1PublicKey(k),
			Type: "PKCS1",
		}, nil
	}

	data, err := x509.MarshalPKIXPublicKey(p)

	if err != nil {
		return nil, err
	}

	return &PublicKeyReply{
		Data: data,
		Type: "PKIX",
	}, nil
}
