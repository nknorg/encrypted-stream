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
  encrypt/decrypt needs to be provided. `XSalsa20Poly1305Cipher` is provided as
  reference.

- The encrypted stream only adds a small constant memory overhead compared to
  the original stream.

## Documentation

Full documentation can be found at
[GoDoc](https://godoc.org/github.com/nknorg/encrypted-stream).

## Usage

Assume you have a `net.Conn` and you want to transform it into an encrypted
`net.Conn`:

```go
conn, err := net.Dial("tcp", "host:port")
```

You first need to have a shared key at both side of the connection, (e.g.
derived from  key exchange algorithm, or pre-determined). Then all you
need to do is to choose or implements a cipher:

```go
encryptedConn, err := stream.NewEncryptedStream(conn, &stream.Config{
  Cipher: stream.NewXSalsa20Poly1305Cipher(&key),
})
```

Now you can use `encryptedConn` just like `conn`, but everything is encrypted
and authenticated.

See [stream_test.go](stream_test.go) for complete example and benchmark with TCP
connection.

## Benchmark

The following benchmark is using XSalsa20Poly1305Cipher
(`golang.org/x/crypto/nacl/secretbox`).

```
$ go test -v -bench=.
=== RUN   TestPipe
--- PASS: TestPipe (0.01s)
=== RUN   TestTCP
--- PASS: TestTCP (0.01s)
goos: darwin
goarch: amd64
pkg: github.com/nknorg/encrypted-stream
BenchmarkPipe-12    	    3867	    260929 ns/op	 502.33 MB/s	     292 B/op	       9 allocs/op
BenchmarkTCP-12     	    6603	    215170 ns/op	 609.16 MB/s	     288 B/op	       9 allocs/op
PASS
ok  	github.com/nknorg/encrypted-stream	2.509s
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
