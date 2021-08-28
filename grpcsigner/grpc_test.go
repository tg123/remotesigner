package grpcsigner_test

import (
	context "context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net"
	"testing"

	"github.com/tg123/remotesigner"
	"github.com/tg123/remotesigner/grpcsigner"
	pb "github.com/tg123/remotesigner/grpcsigner"
	grpc "google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedSignerServer
	privateKey *rsa.PrivateKey
	cert       []byte
}

func newserver() *server {
	s := &server{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	s.privateKey = privateKey

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	s.cert = cert

	return s
}

func (s *server) Sign(_ context.Context, req *grpcsigner.SignRequest) (*grpcsigner.SignReply, error) {
	sig, err := s.privateKey.Sign(rand.Reader, req.Digest, &remotesigner.SignerOpts{
		Algorithm: remotesigner.SignerAlgorithm(req.Algorithm),
	})

	if err != nil {
		return nil, err
	}

	return &grpcsigner.SignReply{
		Signature: sig,
	}, nil
}

func (s *server) PublicKey(_ context.Context, _ *grpcsigner.PublicKeyRequest) (*grpcsigner.PublicKeyReply, error) {
	cert, err := x509.ParseCertificate(s.cert)
	if err != nil {
		panic(err)
	}

	k, ok := cert.PublicKey.(*rsa.PublicKey)

	if ok {
		return &grpcsigner.PublicKeyReply{
			Data: x509.MarshalPKCS1PublicKey(k),
			Type: "PKCS1",
		}, nil
	}

	data, err := x509.MarshalPKIXPublicKey(cert.PublicKey)

	if err != nil {
		return nil, err
	}

	return &grpcsigner.PublicKeyReply{
		Data: data,
		Type: "PKIX",
	}, nil
}

func newsigner(impl *server) (crypto.Signer, func()) {

	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	grpcsigner.RegisterSignerServer(s, impl)

	go s.Serve(l)

	conn, err := grpc.Dial(l.Addr().String(), grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		panic(err)
	}
	c := grpcsigner.NewSignerClient(conn)

	signer := remotesigner.New(grpcsigner.New(c))

	return signer, func() {
		conn.Close()
		s.Stop()
	}
}

func TestSign(t *testing.T) {
	impl := newserver()
	signer, clean := newsigner(impl)
	defer clean()

	for _, aglo := range []remotesigner.SignerAlgorithm{
		remotesigner.SignerAlgorithmRsaPkcs256,
		remotesigner.SignerAlgorithmRsaPkcs384,
		remotesigner.SignerAlgorithmRsaPkcs512,
	} {

		t.Run(string(aglo), func(t *testing.T) {
			opt := &remotesigner.SignerOpts{
				Algorithm: aglo,
			}

			msg := make([]byte, opt.HashFunc().Size())

			rand.Read(msg)

			sig, err := signer.Sign(rand.Reader, msg[:], opt)

			if err != nil {
				t.Error(err)
			}

			if err := rsa.VerifyPKCS1v15(&impl.privateKey.PublicKey, opt.HashFunc(), msg[:], sig); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	impl := newserver()
	signer, clean := newsigner(impl)
	defer clean()

	cert, err := x509.ParseCertificate(impl.cert)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.PublicKey.(*rsa.PublicKey).Equal(signer.Public()) {
		t.Error("wrong public key returned")
	}
}
