/*

Package stream is a Golang library that transforms any net.Conn or io.ReadWriter
stream to an encrypted and/or authenticated stream.

1. The encrypted stream implements net.Conn and io.ReadWriter and can be used as
drop-in replacement.

2. Works with any encryption, authentication, or authenticated encryption
algorithm or even arbitrary transformation. Only a cipher that implements
encrypt/decrypt needs to be provided. XSalsa20-Poly1305 and AES-GCM are provided
as reference cipher.

3. The encrypted stream only adds a small constant memory overhead compared to
the original stream.

Note: this library does not handle handshake or key exchange. Handshake should
be done separately before using this library to compute a shared key.

*/
package stream
