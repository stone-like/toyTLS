package x509

import (
	"encoding/binary"
	"errors"
	"time"
)

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

func Str2Time(str string) time.Time {
	var layout = "2006-01-02 15:04:05"
	t, _ := time.Parse(layout, str)
	return t
}
