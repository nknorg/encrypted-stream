package stream

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// EncryptedStream is an encrypted stream. Data are encrypted before writing to
// underlying stream, and are decrypted after reading from underlying stream.
type EncryptedStream struct {
	config  *Config
	stream  io.ReadWriter
	encoder *Encoder
	decoder *Decoder

	lock     sync.RWMutex
	isClosed bool

	readLock        sync.Mutex
	readLenBuffer   []byte
	readBuffer      []byte
	decryptBuffer   []byte
	decryptBufStart int
	decryptBufEnd   int

	writeLock      sync.Mutex
	writeLenBuffer []byte
	encryptBuffer  []byte
}

// NewEncryptedStream creates an EncryptedStream with a given ReadWriter and
// config.
func NewEncryptedStream(stream io.ReadWriter, config *Config) (*EncryptedStream, error) {
	config, err := MergeConfig(DefaultConfig(), config)
	if err != nil {
		return nil, err
	}

	err = config.Verify()
	if err != nil {
		return nil, err
	}

	encoder, err := NewEncoder(config.Cipher, config.Initiator, config.SequentialNonce)
	if err != nil {
		return nil, err
	}

	decoder, err := NewDecoder(config.Cipher, config.Initiator, config.SequentialNonce, config.DisableNonceVerification)
	if err != nil {
		return nil, err
	}

	es := &EncryptedStream{
		config:         config,
		stream:         stream,
		encoder:        encoder,
		decoder:        decoder,
		readBuffer:     make([]byte, config.MaxChunkSize+config.Cipher.MaxOverhead()+config.Cipher.NonceSize()),
		encryptBuffer:  make([]byte, config.MaxChunkSize+config.Cipher.MaxOverhead()+config.Cipher.NonceSize()),
		decryptBuffer:  make([]byte, config.MaxChunkSize),
		readLenBuffer:  make([]byte, 4),
		writeLenBuffer: make([]byte, 4),
	}

	return es, nil
}

// IsClosed returns whether the EncryptedStream is closed.
func (es *EncryptedStream) IsClosed() bool {
	es.lock.RLock()
	defer es.lock.RUnlock()
	return es.isClosed
}

// Read implements net.Conn and io.Reader
func (es *EncryptedStream) Read(b []byte) (int, error) {
	if es.IsClosed() {
		return 0, io.ErrClosedPipe
	}

	es.readLock.Lock()
	defer es.readLock.Unlock()

	if es.decryptBufStart >= es.decryptBufEnd {
		n, err := readVarBytes(es.stream, es.readBuffer, es.readLenBuffer)
		if err != nil {
			return 0, err
		}

		if n > es.config.MaxChunkSize+es.config.Cipher.MaxOverhead()+es.config.Cipher.NonceSize() {
			return 0, fmt.Errorf("received invalid encrypted data size %d", n)
		}

		es.decryptBuffer = es.decryptBuffer[:cap(es.decryptBuffer)]
		es.decryptBuffer, err = es.decoder.Decode(es.decryptBuffer, es.readBuffer[:n])
		if err != nil {
			return 0, err
		}

		es.decryptBufStart = 0
		es.decryptBufEnd = len(es.decryptBuffer)
	}

	n := copy(b, es.decryptBuffer[es.decryptBufStart:es.decryptBufEnd])
	es.decryptBufStart += n

	return n, nil
}

// Write implements net.Conn and io.Writer
func (es *EncryptedStream) Write(b []byte) (int, error) {
	if es.IsClosed() {
		return 0, io.ErrClosedPipe
	}

	es.writeLock.Lock()
	defer es.writeLock.Unlock()

	bytesWrite := 0
	var err error
	for bytesWrite < len(b) {
		n := len(b) - bytesWrite
		if n > es.config.MaxChunkSize {
			n = es.config.MaxChunkSize
		}

		es.encryptBuffer = es.encryptBuffer[:cap(es.encryptBuffer)]
		es.encryptBuffer, err = es.encoder.Encode(es.encryptBuffer, b[bytesWrite:bytesWrite+n])
		if err != nil {
			return bytesWrite, err
		}

		err = writeVarBytes(es.stream, es.encryptBuffer, es.writeLenBuffer)
		if err != nil {
			return bytesWrite, err
		}

		bytesWrite += n
	}

	return bytesWrite, nil
}

// Close implements net.Conn and io.Closer. Will call underlying stream's
// Close() method if it has one.
func (es *EncryptedStream) Close() error {
	es.lock.Lock()
	defer es.lock.Unlock()

	if es.isClosed {
		return nil
	}

	if stream, ok := es.stream.(io.Closer); ok {
		return stream.Close()
	}

	es.isClosed = true

	return nil
}

// LocalAddr implements net.Conn. Will call underlying stream's LocalAddr()
// method if it has one, otherwise will return nil.
func (es *EncryptedStream) LocalAddr() net.Addr {
	if stream, ok := es.stream.(interface{ LocalAddr() net.Addr }); ok {
		return stream.LocalAddr()
	}
	return nil
}

// RemoteAddr implements net.Conn. Will call underlying stream's RemoteAddr()
// method if it has one, otherwise will return nil.
func (es *EncryptedStream) RemoteAddr() net.Addr {
	if stream, ok := es.stream.(interface{ RemoteAddr() net.Addr }); ok {
		return stream.RemoteAddr()
	}
	return nil
}

// SetDeadline implements net.Conn. Will call underlying stream's SetDeadline()
// method if it has one, otherwise will return nil.
func (es *EncryptedStream) SetDeadline(t time.Time) error {
	if stream, ok := es.stream.(interface{ SetDeadline(t time.Time) error }); ok {
		return stream.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline implements net.Conn. Will call underlying stream's
// SetReadDeadline() method if it has one, otherwise will return nil.
func (es *EncryptedStream) SetReadDeadline(t time.Time) error {
	if stream, ok := es.stream.(interface{ SetReadDeadline(t time.Time) error }); ok {
		return stream.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline implements net.Conn. Will call underlying stream's
// SetWriteDeadline() method if it has one, otherwise will return nil.
func (es *EncryptedStream) SetWriteDeadline(t time.Time) error {
	if stream, ok := es.stream.(interface{ SetWriteDeadline(t time.Time) error }); ok {
		return stream.SetWriteDeadline(t)
	}
	return nil
}
