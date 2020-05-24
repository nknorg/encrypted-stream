package stream

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

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
	if len(b) > math.MaxUint32 {
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
