package tls

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

//なんでTestReadに戻るとtlsConnの情報が消える？
func TestRead(t *testing.T) {

	certByte, err := GetContentFromFIle("../testData/server.crt")
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certByte)
	require.NoError(t, err)

	option := NewTLSOption()

	osFn := func() (*x509.CertPool, error) {
		pool, err := option.OSPool()
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
		return pool, nil
	}

	tlsConn := &TLSConnect{
		OverBuffer: &bytes.Buffer{},
		Option:     NewTLSOption(OSPool(osFn)),
	}

	b1, err := tlsConn.CreateHello(SERVER_HELLO)
	require.NoError(t, err)
	b2, err := tlsConn.CreateCertificate([]string{"../testData/server.crt"})
	require.NoError(t, err)
	b3, err := tlsConn.CreateHelloDone()
	require.NoError(t, err)

	bb := bytes.NewBuffer(MultiAppend(b1, b2, b3))

	tlsConn.Read(bb)

	require.Equal(t, len(tlsConn.Data), 2064)

	recvData := tlsConn.Data[1032:]
	require.True(t, bytes.Equal(recvData, tlsConn.Data[:1032]))
	pubBytes, err := GetContentFromFIle("../testData/pub.key")
	require.NoError(t, err)

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubBytes)
	require.NoError(t, err)

	wantPubKey := pubKeyInterface.(*rsa.PublicKey)

	gotPubKey := tlsConn.PubKey

	if diff := cmp.Diff(gotPubKey, wantPubKey); diff != "" {
		t.Errorf("diff is %s\n", diff)
	}
}

func TestDecryptPreMaster(t *testing.T) {
	pubBytes, err := GetContentFromFIle("../testData/pub.key")
	require.NoError(t, err)

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubBytes)
	require.NoError(t, err)

	pubKey := pubKeyInterface.(*rsa.PublicKey)

	privBytes, err := GetContentFromFIle("../testData/private.key")
	require.NoError(t, err)
	privKey, err := x509.ParsePKCS1PrivateKey(privBytes)
	require.NoError(t, err)

	preMasterSecret := NewPreMasterSecret()
	exchange, _, err := NewKeyExchange(pubKey, preMasterSecret)
	require.NoError(t, err)

	decryptedPreJMaster, err := decryptPreMaster(exchange.PreMasterSecret, privKey)
	require.NoError(t, err)

	require.True(t, bytes.Equal(preMasterSecret.ToByte(), decryptedPreJMaster))

}
