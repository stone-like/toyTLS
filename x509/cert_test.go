package x509

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	data, err := GetContentFromFIle("../testData/server.crt")
	require.NoError(t, err)

	p := NewCertParser(data)

	cert, err := p.Parse()
	require.NoError(t, err)

	ok := cert.Verify()
	require.True(t, ok)
}
