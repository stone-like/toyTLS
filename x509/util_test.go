package x509

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBytes2Int(t *testing.T) {
	b := []byte{0x03, 0x49}
	got, err := Bytes2Int(b)
	require.NoError(t, err)
	want := 841
	require.Equal(t, want, got)

	b = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x49}
	_, err = Bytes2Int(b)
	require.Error(t, err)
}
