package tls

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"os"
	"reflect"
	"strings"
)

func write1byte(l uint8) []byte {
	bytes := make([]byte, 1)
	bytes[0] = byte(l)
	return bytes
}

func write2byte(l uint16) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, l)
	return bytes
}

func write3byte(l uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, l)
	return bytes[1:]
}

//構造体としての情報を入れてByte化するのではなく、中身だけをbyte化
func ToByte(s interface{}) []byte {

	rv := reflect.ValueOf(s)

	var bytes []byte

	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		bytes = append(bytes, b...)
	}

	return bytes
}

func GetContentFromFIle(name string) ([]byte, error) {
	content, err := GetContent(name)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(content)
}

func GetContent(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	var builder strings.Builder
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "-") {
			continue
		}
		ss := scanner.Text()
		builder.WriteString(ss)
	}

	return builder.String(), nil
}
