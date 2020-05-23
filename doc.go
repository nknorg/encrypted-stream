/*

Package stream is a Golang library that transforms any `net.Conn` or
`io.ReadWriter` stream to an encrypted stream with any provided encrypt/decrypt
function.

1. Works with any encryption/authentication algorithm or even general
transformation. Only a pair of encrypt/decrypt function needs to be provided.

2. The encrypted stream implements `net.Conn` and `io.ReadWriter` and can be
used transparently.

3. An encrypted stream only adds a small constant memory overhead compared to
the original stream.

*/
package stream
