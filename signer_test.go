package remotesigner_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/tg123/remotesigner"
)

type mockRemoteSigner struct {
	lastCtx    context.Context
	lastDigest []byte
	lastAlgo   remotesigner.SigAlgo
}

type testContextKey string

func (m *mockRemoteSigner) Sign(ctx context.Context, digest []byte, algo remotesigner.SigAlgo) ([]byte, error) {
	m.lastCtx = ctx
	m.lastDigest = digest
	m.lastAlgo = algo
	return []byte("sig"), nil
}

func (m *mockRemoteSigner) Public() crypto.PublicKey {
	return nil
}

func TestSignerOptsHashFunc(t *testing.T) {
	opts := &remotesigner.SignerOpts{Algorithm: remotesigner.SigAlgoRsaPkcsSHA256}
	if opts.HashFunc() != crypto.SHA256 {
		t.Fatalf("expected SHA256, got %v", opts.HashFunc())
	}
}

func TestSignWithSignerOpts(t *testing.T) {
	impl := &mockRemoteSigner{}
	signer := remotesigner.New(impl)

	digest := make([]byte, crypto.SHA256.Size())

	ctx := context.WithValue(context.Background(), testContextKey("k"), "v")
	sig, err := signer.Sign(rand.Reader, digest, &remotesigner.SignerOpts{
		Algorithm: remotesigner.SigAlgoRsaPkcsSHA256,
		Context:   ctx,
	})
	if err != nil {
		t.Fatal(err)
	}

	if string(sig) != "sig" {
		t.Fatalf("unexpected signature: %q", sig)
	}

	if impl.lastCtx != ctx {
		t.Fatal("expected context from options")
	}
	if impl.lastAlgo != remotesigner.SigAlgoRsaPkcsSHA256 {
		t.Fatalf("unexpected algorithm: %s", impl.lastAlgo)
	}
}

func TestSignWithPSSOptions(t *testing.T) {
	impl := &mockRemoteSigner{}
	signer := remotesigner.New(impl)

	digest := make([]byte, crypto.SHA256.Size())

	_, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}

	if impl.lastAlgo != remotesigner.SigAlgoRsaPssSHA256 {
		t.Fatalf("unexpected algorithm: %s", impl.lastAlgo)
	}
	if impl.lastCtx == nil {
		t.Fatal("expected default context to be set")
	}
}

func TestSignBadDigestLength(t *testing.T) {
	impl := &mockRemoteSigner{}
	signer := remotesigner.New(impl)

	_, err := signer.Sign(rand.Reader, []byte{1, 2, 3}, crypto.SHA256)
	if !errors.Is(err, remotesigner.ErrBadDigest) {
		t.Fatalf("expected bad digest error, got %v", err)
	}
}

func TestSignUnknownAlgorithm(t *testing.T) {
	impl := &mockRemoteSigner{}
	signer := remotesigner.New(impl)

	_, err := signer.Sign(rand.Reader, []byte{1, 2, 3}, &remotesigner.SignerOpts{Algorithm: "UNKNOWN"})
	if !errors.Is(err, remotesigner.ErrUnsupportedHash) {
		t.Fatalf("expected ErrUnsupportedHash, got %v", err)
	}
}

func TestSignUnsupportedHash(t *testing.T) {
	impl := &mockRemoteSigner{}
	signer := remotesigner.New(impl)

	digest := make([]byte, crypto.MD5.Size())

	_, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.MD5})
	if !errors.Is(err, remotesigner.ErrUnsupportedHash) {
		t.Fatalf("expected ErrUnsupportedHash, got %v", err)
	}
}
