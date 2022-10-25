package util

import (
	"encoding/binary"
	"errors"
)

type ZeroSource struct{}

func (ZeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

var (
	ErrInvalidBytesForInt = errors.New("more than 8byte is not matched for int")
)

func Bytes2Int(b []byte) (int, error) {

	if 8 < len(b) {
		return -1, ErrInvalidBytesForInt
	}

	if len(b)%8 == 0 {
		return int(binary.BigEndian.Uint64(b)), nil
	}

	paddingNum := 8 - (len(b) % 8)

	newBytes := make([]byte, len(b)+paddingNum)

	for i := 0; i < paddingNum; i++ {
		newBytes[i] = 0x00
	}
	for i := paddingNum; i < len(newBytes); i++ {
		newBytes[i] = b[i-paddingNum]
	}
	return int(binary.BigEndian.Uint64(newBytes)), nil
}
