package x509

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	data, err := GetContentFromFIle("../testData/server.crt")
	require.NoError(t, err)

	p := NewCertParser(data)

	cert, err := p.Parse()
	require.NoError(t, err)

	bytes, err := os.ReadFile("../testData/pub.key")
	require.NoError(t, err)
	block, _ := pem.Decode(bytes)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	ok := cert.Verify([]crypto.PublicKey{pubKey})
	require.True(t, ok)
}
