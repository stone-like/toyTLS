package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

type DataForDecodeDER struct {
	title    string
	bytes    []byte
	wantData *Data
}

func testDataForDecodeDER() []DataForDecodeDER {

	createBytes := func(num int, fill []byte) []byte {
		ret := make([]byte, num)
		copy(ret, fill)
		return ret
	}

	givens := [][]byte{
		{0x04, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90},
		createBytes(532, []byte{0x30, 0x82, 0x02, 0x10, 0x04, 0x01, 0x56}),
		{0xdf, 0x82, 0x02, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90},
		{0x30, 0x80, 0x04, 0x03, 0x56, 0x78, 0x90, 0x00, 0x00},
	}

	return []DataForDecodeDER{
		{
			title: "normal",
			bytes: givens[0],
			wantData: &Data{
				Class:      0,
				Structured: false,
				Tag:        4,
				ByteLength: 7,
				Contents:   givens[0][2:],
				Raw:        givens[0],
			},
		},
		{
			title: "bigLength",
			bytes: givens[1],
			wantData: &Data{
				Class:      0,
				Structured: true,
				Tag:        16,
				ByteLength: 532,
				Contents:   givens[1][4:],
				Raw:        givens[1],
			},
		},
		{
			title: "bigTag",
			bytes: givens[2],
			wantData: &Data{
				Class:      3,
				Structured: false,
				Tag:        130,
				ByteLength: 9,
				Contents:   givens[2][4:],
				Raw:        givens[2],
			},
		},
		{
			title: "IndeterminateLength",
			bytes: givens[3],
			wantData: &Data{
				Class:      0,
				Structured: true,
				Tag:        16,
				ByteLength: 9,
				Contents:   givens[3][2:7],
				Raw:        givens[3],
			},
		},
	}
}

func TestDecodeDER(t *testing.T) {

	for _, data := range testDataForDecodeDER() {
		t.Run(data.title, func(t *testing.T) {
			p := NewDERParser(data.bytes)
			d, err := p.Parse()
			require.NoError(t, err)
			wantData := data.wantData

			if diff := cmp.Diff(wantData, d); diff != "" {
				t.Errorf("diff is %s\n", diff)
			}
		})
	}
}

func TestDecodeOID(t *testing.T) {
	bytes := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}

	want := "1.2.840.113549.1.1.11"

	got := decodeOID(bytes)

	require.Equal(t, want, got)
}

func TestGetCertContent(t *testing.T) {
	cert, err := GetContentFromFIle("../testData/server.crt")
	require.NoError(t, err)

	want, err := GetContentFromFIle("../testData/certContent.txt")
	require.NoError(t, err)

	require.Equal(t, string(want), cert)
}

func TestCertTest(t *testing.T) {
	f, err := os.Open("../testData/server.crt")
	require.NoError(t, err)

	b, err := ioutil.ReadAll(f)
	require.NoError(t, err)

	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	cert.CheckSignatureFrom(cert)
	fmt.Println(cert)
}

//後々pubKeyのparserを作る
func TestParseCert(t *testing.T) {
	// data, err := GetContentFromFIle("../testData/server.crt")
	// require.NoError(t, err)

	// p := NewCertParser(data)

	// parsed, err := p.Parse()
	// require.NoError(t, err)

	bytes, err := os.ReadFile("../testData/pub.key")
	require.NoError(t, err)
	block, _ := pem.Decode(bytes)
	keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	wantPub, ok := keyInterface.(*rsa.PublicKey)
	require.True(t, ok)
	fmt.Println(wantPub)

	// if diff := cmp.Diff(gotPub, wantPub); diff != "" {
	// 	t.Errorf("diff is: %s\n", diff)
	// }
}
