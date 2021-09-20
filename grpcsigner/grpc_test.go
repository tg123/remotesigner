package grpcsigner_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"

	"github.com/tg123/remotesigner"
	"github.com/tg123/remotesigner/grpcsigner"
	"google.golang.org/grpc"
)

func newserver() (grpcsigner.SignerServer, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return grpcsigner.NewSignerServer(privateKey), privateKey
}

func newsigner() (crypto.Signer, *rsa.PrivateKey, func()) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	impl := grpcsigner.NewSignerServer(privateKey)

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

	return signer, privateKey, func() {
		conn.Close()
		s.Stop()
	}
}

func TestSign(t *testing.T) {
	signer, privateKey, clean := newsigner()
	defer clean()

	for _, aglo := range []remotesigner.SigAlgo{
		remotesigner.SigAlgoRsaPkcsSHA1,
		remotesigner.SigAlgoRsaPkcsSHA224,
		remotesigner.SigAlgoRsaPkcsSHA256,
		remotesigner.SigAlgoRsaPkcsSHA384,
		remotesigner.SigAlgoRsaPkcsSHA512,
		// remotesigner.SigAlgoRsaPkcsSHA512_224,
		// remotesigner.SigAlgoRsaPkcsSHA512_256,
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

			if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, opt.HashFunc(), msg[:], sig); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestPublicKey(t *testing.T) {

	signer, privateKey, clean := newsigner()
	defer clean()

	if !privateKey.PublicKey.Equal(signer.Public()) {
		t.Error("wrong public key returned")
	}
}
