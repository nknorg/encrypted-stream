package stream

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

var (
	// ErrMaxNonce indicates the max allowed nonce is reach. If this happends, a
	// new stream with different key should be created.
	ErrMaxNonce = errors.New("max nonce reached")

	// ErrWrongNonceInitiator indicates a nonce with the wrong party is received,
	// i.e. initiator receives a nonce from initiator, or responder receives a
	// nonce from responder. It is either a configuration error (e.g. both party
	// set initiator to the same value), or a middle man is performing reflection
	// attack.
	ErrWrongNonceInitiator = errors.New("wrong nonce direction")

	// ErrWrongNonceSequential indicates a nonce with the wrong value is received.
	// It is either a configuration error (e.g. one side set sequentialNonce to
	// true, the other side set to false), or a middle man is performing replay,
	// re-order or packet drop attack.
	ErrWrongNonceSequential = errors.New("wrong nonce value")
)

// Encoder provides encode function of a slice data.
type Encoder struct {
	cipher          Cipher
	initiator       bool
	sequentialNonce bool
	nextNonce       []byte
	maxNonce        []byte
}

// NewEncoder creates a Encoder with given cipher and config.
func NewEncoder(cipher Cipher, initiator, sequentialNonce bool) (*Encoder, error) {
	encoder := &Encoder{
		cipher:          cipher,
		initiator:       initiator,
		sequentialNonce: sequentialNonce,
		nextNonce:       initNonce(cipher.NonceSize(), initiator),
		maxNonce:        maxNonce(cipher.NonceSize(), initiator),
	}

	return encoder, nil
}

// Encode encodes a plaintext to nonce + ciphertext. When sequential nonce is
// true, Encode is not thread safe and should not be called concurrently.
func (e *Encoder) Encode(ciphertext, plaintext []byte) ([]byte, error) {
	nonceSize := e.cipher.NonceSize()

	if e.sequentialNonce {
		if bytes.Compare(e.nextNonce, e.maxNonce) >= 0 {
			return nil, ErrMaxNonce
		}
		copy(ciphertext[:nonceSize], e.nextNonce)
		incrementNonce(e.nextNonce)
	} else {
		_, err := rand.Read(ciphertext[:nonceSize])
		if err != nil {
			return nil, err
		}

		if e.initiator {
			ciphertext[0] &= 127
		} else {
			ciphertext[0] |= 128
		}
	}

	encrypted, err := e.cipher.Encrypt(ciphertext[nonceSize:], plaintext, ciphertext[:nonceSize])
	if err != nil {
		return nil, err
	}

	return ciphertext[:nonceSize+len(encrypted)], nil
}

// Decoder provides decode function of a slice data.
type Decoder struct {
	cipher                   Cipher
	initiator                bool
	sequentialNonce          bool
	disableNonceVerification bool
	nextNonce                []byte
}

// NewDecoder creates a Decoder with given cipher and config.
func NewDecoder(cipher Cipher, initiator, sequentialNonce, disableNonceVerification bool) (*Decoder, error) {
	decoder := &Decoder{
		cipher:                   cipher,
		initiator:                initiator,
		sequentialNonce:          sequentialNonce,
		disableNonceVerification: disableNonceVerification,
		nextNonce:                initNonce(cipher.NonceSize(), !initiator),
	}

	return decoder, nil
}

// Decode decodes a nonce + ciphertext to plaintext. When sequential nonce is
// true, Decode is not thread safe and should not be called concurrently.
func (d *Decoder) Decode(plaintext, ciphertext []byte) ([]byte, error) {
	nonceSize := d.cipher.NonceSize()
	if len(ciphertext) <= nonceSize {
		return nil, fmt.Errorf("invalid ciphertext size %d", len(ciphertext))
	}

	nonce := ciphertext[:nonceSize]
	if !d.disableNonceVerification {
		if d.initiator {
			if nonce[0]>>7 != 1 {
				return nil, ErrWrongNonceInitiator
			}
		} else {
			if nonce[0]>>7 != 0 {
				return nil, ErrWrongNonceInitiator
			}
		}

		if d.sequentialNonce {
			if !bytes.Equal(nonce, d.nextNonce) {
				return nil, ErrWrongNonceSequential
			}
		}
	}

	plaintext, err := d.cipher.Decrypt(plaintext, ciphertext[nonceSize:], nonce)
	if err != nil {
		return nil, err
	}

	if d.sequentialNonce {
		incrementNonce(d.nextNonce)
	}

	return plaintext, nil
}

func initNonce(nonceSize int, initiator bool) []byte {
	b := make([]byte, nonceSize)
	if !initiator {
		b[0] |= 128
	}
	return b
}

func maxNonce(nonceSize int, initiator bool) []byte {
	b := make([]byte, nonceSize)
	for i := 0; i < len(b); i++ {
		b[i] = 255
	}
	if initiator {
		b[0] &= 127
	}
	return b
}

func incrementNonce(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] > 0 {
			break
		}
	}
}

func readVarBytes(reader io.Reader, b, lenBuf []byte) (int, error) {
	if len(lenBuf) < 4 {
		lenBuf = make([]byte, 4)
	}

	_, err := io.ReadFull(reader, lenBuf)
	if err != nil {
		return 0, err
	}

	n := int(binary.LittleEndian.Uint32(lenBuf))
	if len(b) < n {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(reader, b[:n])
}

func writeVarBytes(writer io.Writer, b, lenBuf []byte) error {
	if len(b) > math.MaxInt32 {
		return errors.New("data size too large")
	}

	if len(lenBuf) < 4 {
		lenBuf = make([]byte, 4)
	}

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(b)))

	_, err := writer.Write(lenBuf)
	if err != nil {
		return err
	}

	_, err = writer.Write(b)
	if err != nil {
		return err
	}

	return nil
}
