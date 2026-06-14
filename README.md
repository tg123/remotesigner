# remotesigner

[![Go Reference](https://pkg.go.dev/badge/github.com/tg123/remotesigner.svg)](https://pkg.go.dev/github.com/tg123/remotesigner)

`crypto.Signer` backed by a remote service — gRPC, REST or anything else.

`remotesigner` lets you keep private keys outside your application process. Your
code holds only a thin `crypto.Signer` that forwards every signing operation to a
remote backend (an HSM, a KMS, a signing microservice, ...), so the key material
never has to live in the same process — or even the same machine — as the code
that uses it.

## Features

- Implements the standard library [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)
  interface, so it works as a drop-in with `crypto/tls`, `crypto/x509` and any
  library that accepts a `crypto.Signer`.
- Backend-agnostic: implement the small `RemoteSigner` interface over any
  transport you like.
- A ready-to-use gRPC backend is included under [`grpcsigner`](./grpcsigner).
- Supports RSA PKCS#1 v1.5, RSA-PSS and ECDSA over MD5/SHA-1/SHA-224/SHA-256/
  SHA-384/SHA-512 digests.

## Installation

```bash
go get github.com/tg123/remotesigner
```

## Usage

### Implementing a backend

Provide a type that satisfies `RemoteSigner`:

```go
type RemoteSigner interface {
	Sign(ctx context.Context, digest []byte, algo SigAlgo) ([]byte, error)
	Public() crypto.PublicKey
}
```

Then wrap it into a `crypto.Signer`:

```go
signer := remotesigner.New(myRemoteSigner)

// use signer anywhere a crypto.Signer is expected, e.g. crypto/tls
```

### Using the gRPC backend

The `grpcsigner` package implements `RemoteSigner` on top of gRPC.

**Client side** — turn a gRPC connection into a `crypto.Signer`:

```go
import (
	"github.com/tg123/remotesigner"
	"github.com/tg123/remotesigner/grpcsigner"
)

conn, err := grpc.Dial(addr, grpc.WithInsecure())
// handle err

client := grpcsigner.NewSignerClient(conn)
signer := remotesigner.New(grpcsigner.New(client, "" /* metadata */))
```

**Server side** — expose your local keys over gRPC:

```go
impl, err := grpcsigner.NewSignerServer(func(metadata string) (crypto.Signer, error) {
	// resolve the key for the given metadata
	return privateKey, nil
})
// handle err

s := grpc.NewServer()
grpcsigner.RegisterSignerServer(s, impl)
s.Serve(listener)
```

The `metadata` string is passed through on every request, letting the server pick
which key to use per call.

## Signature algorithms

`SignerOpts` selects the algorithm explicitly. When using `crypto.SignerOpts`
directly, the digest size determines the hash and the algorithm is inferred
(`rsa.PSSOptions` → RSA-PSS, otherwise RSA PKCS#1 v1.5). Supported values include:

- `RSASSA_PKCS1_V1_5_*` (MD5, SHA-1/224/256/384/512)
- `RSASSA_PSS_*` (SHA-1/224/256/384/512)
- `ECDSA_*` (SHA-1/224/256/384/512)

## Testing

```bash
go test ./...
```

## License

See [LICENSE](./LICENSE).
