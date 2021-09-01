# encrypted-stream

[![GoDoc](https://godoc.org/github.com/nknorg/encrypted-stream?status.svg)](https://godoc.org/github.com/nknorg/encrypted-stream)
[![GitHub
license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Report
Card](https://goreportcard.com/badge/github.com/nknorg/encrypted-stream)](https://goreportcard.com/report/github.com/nknorg/encrypted-stream)
[![Build
Status](https://travis-ci.org/nknorg/encrypted-stream.svg?branch=master)](https://travis-ci.org/nknorg/encrypted-stream)
[![PRs
Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

Encrypted-stream is a Golang library that transforms any `net.Conn` or
`io.ReadWriter` stream to an encrypted and/or authenticated stream.

- The encrypted stream implements `net.Conn` and `io.ReadWriter` and can be used
  as drop-in replacement.

- Works with any encryption, authentication, or authenticated encryption
  algorithm or even arbitrary transformation. Only a cipher that implements
  encrypt/decrypt needs to be provided. XSalsa20-Poly1305 and AES-GCM are
  provided as reference cipher.

- The encrypted stream only adds a small constant memory overhead compared to
  the original stream.

Note: this library does not handle handshake or key exchange. Handshake should
be done separately before using this library to compute a shared key.

## Documentation

Full documentation can be found at
[GoDoc](https://godoc.org/github.com/nknorg/encrypted-stream).

## Usage

Assume you have a `net.Conn` and you want to transform it into an encrypted
`net.Conn`:

```go
conn, err := net.Dial("tcp", "host:port")
```

You first need to have a shared key at both side of the connection (e.g.
derived from  key exchange algorithm). Then all you need to do is to choose or
implements a cipher:

```go
encryptedConn, err := stream.NewEncryptedStream(conn, &stream.Config{
  Cipher: stream.NewXSalsa20Poly1305Cipher(&key),
  SequentialNonce: true, // only when key is unique for every stream
  Initiator: true, // only on the dialer side
})
```

Now you can use `encryptedConn` just like `conn`, but everything is encrypted
and authenticated.

See [stream_test.go](stream_test.go) for complete example and benchmark with TCP
connection.

## Benchmark

```
$ go test -v -bench=. -run=^$
goos: darwin
goarch: amd64
pkg: github.com/nknorg/encrypted-stream
BenchmarkPipeXSalsa20Poly1305-12    	    4064	    266725 ns/op	 491.41 MB/s	       3 B/op	       0 allocs/op
BenchmarkPipeAESGCM128-12           	   16195	     71669 ns/op	1828.86 MB/s	       0 B/op	       0 allocs/op
BenchmarkPipeAESGCM256-12           	   14328	     83337 ns/op	1572.79 MB/s	       0 B/op	       0 allocs/op
BenchmarkTCPXSalsa20Poly1305-12     	    6489	    185980 ns/op	 704.76 MB/s	       0 B/op	       0 allocs/op
BenchmarkTCPAESGCM128-12            	   20089	     59684 ns/op	2196.08 MB/s	       0 B/op	       0 allocs/op
BenchmarkTCPAESGCM256-12            	   17656	     67721 ns/op	1935.48 MB/s	       0 B/op	       0 allocs/op
PASS
ok  	github.com/nknorg/encrypted-stream	9.997s
```

## Contributing

**Can I submit a bug, suggestion or feature request?**

Yes. Please open an issue for that.

**Can I contribute patches?**

Yes, we appreciate your help! To make contributions, please fork the repo, push
your changes to the forked repo with signed-off commits, and open a pull request
here.

Please sign off your commit. This means adding a line "Signed-off-by: Name
<email>" at the end of each commit, indicating that you wrote the code and have
the right to pass it on as an open source patch. This can be done automatically
by adding -s when committing:

```shell
git commit -s
```

## Community

- [Forum](https://forum.nkn.org/)
- [Discord](https://discord.gg/c7mTynX)
- [Telegram](https://t.me/nknorg)
- [Reddit](https://www.reddit.com/r/nknblockchain/)
- [Twitter](https://twitter.com/NKN_ORG)
