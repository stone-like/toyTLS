package tls

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptMessage(t *testing.T) {

	message := []byte("hello world12345")
	writeKey := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	iv := []byte{0x00, 0x00, 0x00, 0x02}
	seqNum := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}

	addtionalData := []byte("someAdditionalData")

	nonce := append(Copy(iv), seqNum...)

	gcm, err := NewGCM(writeKey)
	require.NoError(t, err)

	cipherText, err := gcm.EncryptMessage(writeKey, nonce, message, addtionalData)
	require.NoError(t, err)
	decrypted, err := gcm.DecryptedMessage(writeKey, nonce, cipherText, addtionalData)
	require.NoError(t, err)

	require.True(t, bytes.Equal(message, decrypted))

}
