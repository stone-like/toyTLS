package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"

	"github.com/stonelike/toytls/debug/util"
)

var (
	ErrUnknownHandShake = errors.New("this handshakeType is unknown")
	ErrFinishedVerify   = errors.New("failed to verifyData")
)

//TLSRecordLayer
// Message
//という構造

//TLSRecordLayerは
//MessageType 1byte
//Version 2byte
//Length 2byte

//MessageTypeは4種類
//ChangeCipherSpec 0x14
//Alert 0x15
//Handshake 0x16
//Application Data 0x17

var (
	PROTOCOL_MAJOR = 3
	PROTOCOL_MINOR = 1
)

type MessageType int

const (
	CHANGE_CIPHER_SPEC MessageType = 20
	ALERT              MessageType = 21
	HANDSHAKE          MessageType = 22
	APPLICATION_DATA   MessageType = 23
)

// type AlertLevel int
// const (
// 	WARNING AlertLevel = 1
// 	FATAL AlertLevel = 2
// )

// type AlertDescription int
// const (
// 	close_notify AlertDescription = 0
// 	unexpected_message AlertDescription = 10
// 	bad_record_mac AlertDescription = 20
// 	decryption_failed = 21
// 	record_overflow = 22
// 	decompression_failure = 30
// 	handshake_failure = 40
// 	bad_certificate = 42
// 	unsupported_certificate = 43
// 	certificate_revoked = 44
// 	certificate_expired = 45
// 	certificate_unknown = 46
// 	illegal_parameter = 47
// 	unknown_ca = 48
// 	access_denied = 49
// 	decode_error = 50
// 	decrypt_error = 51
// 	export_restriction = 60
// 	protocol_version = 70
// 	insufficient_security = 71
// 	internal_error = 80
// 	user_canceled = 90
// 	no_renegotiation = 100
// )

type HandShakeType int

const (
	HELLO_REQUEST       HandShakeType = 0
	CLIENT_HELLO        HandShakeType = 1
	SERVER_HELLO        HandShakeType = 2
	CERTIFICATE         HandShakeType = 11
	SERVER_KEY_EXCHANGE HandShakeType = 12
	CERTIFICATE_REQUEST HandShakeType = 13
	SERVER_HELLO_DONE   HandShakeType = 14
	CERTIFICATE_VERIFY  HandShakeType = 15
	CLIENT_KEY_EXCHANGE HandShakeType = 16
	FINISHED            HandShakeType = 20
)

var (
	CLIENT_MAJOR = 3
	CLIENT_MINOR = 3
)

type TLSRecord struct {
	Type    []byte //1byte
	Version []byte //2byte
	Len     []byte //2byte
}

func (t *TLSRecord) ToByte() []byte {
	return ToByte(*t)
}

type HandShakeHeader struct {
	Type   []byte
	Length []byte //3byte
}

func (h *HandShakeHeader) Len() int {
	return len(h.Type) + len(h.Length)
}

func (h *HandShakeHeader) ToByte() []byte {
	return ToByte(*h)
}

var generateRandom = defaultRandom

func defaultRandom() []byte {
	bytes := make([]byte, 32)
	return bytes
}

var generateSession = defaultSession

func defaultSession() []byte {
	bytes := make([]byte, 32)
	return bytes
}

type Hello struct {
	Version            []byte
	Random             []byte
	SessionIDLength    []byte
	SessionID          []byte
	CipherSuitesLength []byte
	CipherSuites       []byte
	CompressionLength  []byte
	CompressionMethod  []byte
}

func NewHello() *Hello {
	Hello := &Hello{
		Version:            []byte{byte(CLIENT_MAJOR), byte(CLIENT_MINOR)},
		Random:             generateRandom(),
		SessionIDLength:    []byte{0x20},
		SessionID:          generateSession(),
		CipherSuitesLength: []byte{0x00, 0x02},
		CipherSuites:       []byte{0x00, 0x9c},
		CompressionLength:  []byte{0x01},
		CompressionMethod:  []byte{0x00},
	}
	return Hello
}

func (h *Hello) Len() int {
	length := len(h.Version) + len(h.Random) + len(h.SessionIDLength) + len(h.SessionID) +
		len(h.CipherSuitesLength) + len(h.CipherSuites) + len(h.CompressionLength) + len(h.CompressionMethod)

	return length
}

func (h *Hello) ToByte() []byte {
	return ToByte(*h)
}
func (h *Hello) ToStruct(bytes []byte) error {
	h.Version = bytes[0:2]
	h.Random = bytes[2:34]
	h.SessionIDLength = []byte{bytes[24]}
	h.SessionID = bytes[25:57]
	h.CipherSuitesLength = bytes[57:59]
	h.CipherSuites = bytes[59:61]
	h.CompressionLength = []byte{bytes[61]}
	h.CompressionMethod = []byte{bytes[62]}

	//残りはExtensionだが今回は未実装
	return nil
}

func (t *TLSConnect) CreateHello(handShakeType HandShakeType) ([]byte, error) {

	hello := NewHello()

	if handShakeType == CLIENT_HELLO {
		t.ClientRandom = hello.Random
	} else {
		t.ServerRandom = hello.Random
	}

	lenByte := write3byte(uint32(hello.Len()))

	header := &HandShakeHeader{
		Type:   []byte{byte(handShakeType)},
		Length: lenByte,
	}

	recordLenByte := write2byte(uint16(header.Len() + hello.Len()))
	tlsRecord := &TLSRecord{
		Type:    []byte{byte(HANDSHAKE)},
		Version: []byte{0x03, 0x01},
		Len:     recordLenByte,
	}

	headerBytes := header.ToByte()
	helloBytes := hello.ToByte()
	t.AddData(headerBytes)
	t.AddData(helloBytes)

	var buf bytes.Buffer
	buf.Write(tlsRecord.ToByte())
	buf.Write(headerBytes)
	buf.Write(helloBytes)

	return buf.Bytes(), nil
}

func (t *TLSConnect) SendHello(handShakeType HandShakeType) error {

	bytes, err := t.CreateHello(handShakeType)
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

type Certificate struct {
	CertificateLen []byte //全証明書のtotal長さ(長さ＋証明書の長さではなく証明書自体の長さを足し合わせたもの)
	ContentList    []*CertificateContent
}

type CertificateContent struct {
	Len  []byte
	Cert []byte
}

func (c *CertificateContent) ToByte() []byte {
	return ToByte(*c)
}

func getCertificates(names []string) ([][]byte, error) {
	certs := make([][]byte, len(names))

	for i, name := range names {
		cert, err := GetContentFromFIle(name)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}

func NewCertificate(names []string) (*Certificate, error) {

	certs, err := getCertificates(names)
	if err != nil {
		return nil, err
	}

	contentList := make([]*CertificateContent, len(certs))
	certLen := 0
	for i, cert := range certs {
		contentList[i] = &CertificateContent{
			Len:  write3byte(uint32(len(cert))),
			Cert: cert,
		}
		certLen += len(cert)
	}

	return &Certificate{
		CertificateLen: write3byte(uint32(certLen)),
		ContentList:    contentList,
	}, nil
}

func (c *Certificate) Len() int {
	return len(c.ToByte())
}

func (c *Certificate) ToByte() []byte {

	bytes := c.CertificateLen

	for _, content := range c.ContentList {
		bytes = append(bytes, content.ToByte()...)
	}

	return bytes
}

func (c *Certificate) ToStruct(bytes []byte) error {

	c.CertificateLen = bytes[0:3]
	totalCertLen, err := util.Bytes2Int(bytes[0:3])
	if err != nil {
		return err
	}

	content := bytes[3:]

	var certContentList []*CertificateContent

	start := 0

	for totalCertLen > 0 {
		certLenEnd := start + 3
		certLen, err := util.Bytes2Int(content[start:certLenEnd])
		if err != nil {
			return err
		}
		cert := content[certLenEnd : certLenEnd+certLen]

		certContentList = append(certContentList, &CertificateContent{
			Len:  content[start:certLenEnd],
			Cert: cert,
		})

		start = certLenEnd + certLen
		totalCertLen -= certLen

	}

	c.ContentList = certContentList

	return nil

}

//TODO rsa以外にも対応
func (c *Certificate) GetPublicKey(getOSPool func() (*x509.CertPool, error)) (*rsa.PublicKey, error) {
	certs, err := c.Verify(getOSPool)
	if err != nil {
		return nil, err
	}

	pubKey := certs[0].PublicKey.(*rsa.PublicKey)
	return pubKey, nil
}

//windowsでもcertPoolを読み込めるように対応
//参考
//https://qiita.com/frozenbonito/items/bb615e09dcee3175ef5a
func defaultOSPool() (*x509.CertPool, error) {
	systemPool, err := x509.SystemCertPool()
	if err == nil {
		return systemPool, nil
	}

	sum, err := getSHA256Sum()
	if err != nil {
		return nil, err
	}
	pem, err := getPEM(sum)
	if err != nil {
		return nil, err
	}

	certpool := x509.NewCertPool()

	if !certpool.AppendCertsFromPEM(pem) {
		return nil, errors.New("Failed to Append Certs From PEM")
	}

	return certpool, nil
}

const (
	caCertPEMURL    = "https://curl.se/ca/cacert.pem"
	caCertSHA256URL = "https://curl.se/ca/cacert.pem.sha256"
)

func getSHA256Sum() ([]byte, error) {
	res, err := http.DefaultClient.Get(caCertSHA256URL)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error, %s", res.Status)
	}

	return io.ReadAll(res.Body)
}

func getPEM(sha256Sum []byte) ([]byte, error) {
	res, err := http.DefaultClient.Get(caCertPEMURL)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error, %s", res.Status)
	}

	h := sha256.New()
	r := io.TeeReader(res.Body, h)

	pem, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	fileSum := []byte(fmt.Sprintf("%x  %s\n", h.Sum(nil), path.Base(caCertPEMURL)))
	if !bytes.Equal(fileSum, sha256Sum) {
		return nil, errors.New("failed to verify checksum")
	}

	return pem, nil
}

func (c *Certificate) Verify(getOSPool func() (*x509.CertPool, error)) ([]*x509.Certificate, error) {
	ospool, err := getOSPool()
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	for _, content := range c.ContentList {
		cert, err := x509.ParseCertificate(content.Cert)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}
	//[0]サーバー証明書 -> [1]中間証明書の順に格納されているので、
	//逆から回す
	for i := len(certs) - 1; i >= 0; i-- {
		opts := x509.VerifyOptions{
			Roots: ospool,
		}
		_, err := certs[i].Verify(opts)
		if err != nil {
			return nil, err
		}

		ospool.AddCert(certs[i])
	}

	return certs, nil

}

func (t *TLSConnect) CreateCertificate(names []string) ([]byte, error) {
	certificate, err := NewCertificate(names)
	if err != nil {
		return nil, err
	}

	lenByte := write3byte(uint32(certificate.Len()))

	header := &HandShakeHeader{
		Type:   []byte{byte(CERTIFICATE)},
		Length: lenByte,
	}

	recordLenByte := write2byte(uint16(header.Len() + certificate.Len()))
	tlsRecord := &TLSRecord{
		Type:    []byte{byte(HANDSHAKE)},
		Version: []byte{0x03, 0x01},
		Len:     recordLenByte,
	}

	headerBytes := header.ToByte()
	certificateBytes := certificate.ToByte()
	t.AddData(headerBytes)
	t.AddData(certificateBytes)

	var buf bytes.Buffer
	buf.Write(tlsRecord.ToByte())
	buf.Write(headerBytes)
	buf.Write(certificateBytes)

	return buf.Bytes(), nil
}

func (t *TLSConnect) SendCert(names []string) error {

	bytes, err := t.CreateCertificate(names)
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

//HandShakeHeaderのみで良いので空のまま
type ServerHelloDone struct{}

func (t *TLSConnect) CreateHelloDone() ([]byte, error) {

	header := &HandShakeHeader{
		Type:   []byte{byte(SERVER_HELLO_DONE)},
		Length: []byte{0x00, 0x00, 0x00},
	}

	recordLenByte := write2byte(uint16(header.Len()))
	tlsRecord := &TLSRecord{
		Type:    []byte{byte(HANDSHAKE)},
		Version: []byte{0x03, 0x01},
		Len:     recordLenByte,
	}

	headerBytes := header.ToByte()
	t.AddData(headerBytes)

	var buf bytes.Buffer
	buf.Write(tlsRecord.ToByte())
	buf.Write(headerBytes)

	return buf.Bytes(), nil
}

func (t *TLSConnect) SendHelloDone() error {

	bytes, err := t.CreateHelloDone()
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

var generatePreMaster = defaultPreMaster

func defaultPreMaster() []byte {
	bytes := make([]byte, 46)
	return bytes
}

type PreMasterSecret struct {
	Version []byte //2byte
	Random  []byte //46byte
}

func (p *PreMasterSecret) Len() int {
	return len(p.Version) + len(p.Random)
}

func (p *PreMasterSecret) ToByte() []byte {
	return ToByte(*p)
}

func decryptPreMaster(bytes []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, bytes)
}

type ClientKeyExchange struct {
	Length          []byte //preMasterSecretのlen,2byte
	PreMasterSecret []byte
}

func NewPreMasterSecret() *PreMasterSecret {
	return &PreMasterSecret{
		Version: []byte{byte(CLIENT_MAJOR), byte(CLIENT_MINOR)},
		Random:  generatePreMaster(),
	}
}

func NewKeyExchange(pubKey *rsa.PublicKey, preMasterSecret *PreMasterSecret) (*ClientKeyExchange, []byte, error) {

	//encrypt
	preMasterBytes := preMasterSecret.ToByte()
	secret, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, preMasterBytes)
	if err != nil {
		return nil, nil, err
	}

	return &ClientKeyExchange{
		Length:          write2byte(uint16(len(secret))),
		PreMasterSecret: secret,
	}, preMasterBytes, nil
}

func (c *ClientKeyExchange) Len() int {
	return len(c.Length) + len(c.PreMasterSecret)
}

func (c *ClientKeyExchange) ToByte() []byte {
	return append(c.Length, c.PreMasterSecret...)
}

//後続のchangeCipherSpecまで読み込んでしまうため、byteは制限する
func (c *ClientKeyExchange) ToStruct(bytes []byte) error {
	c.Length = bytes[:2]
	c.PreMasterSecret = bytes[2:]
	return nil
}

func (t *TLSConnect) CreateKeyExchange() ([]byte, error) {

	exchange, decryptedPreMaster, err := NewKeyExchange(t.PubKey, NewPreMasterSecret())
	if err != nil {
		return nil, err
	}

	t.MasterKey = CreateMasterKey(decryptedPreMaster, append(t.ClientRandom, t.ServerRandom...))
	t.KeyBlock = NewKeyBlock(t.MasterKey, append(t.ServerRandom, t.ClientRandom...))

	lenByte := write3byte(uint32(exchange.Len()))

	header := &HandShakeHeader{
		Type:   []byte{byte(CLIENT_KEY_EXCHANGE)},
		Length: lenByte,
	}

	recordLenByte := write2byte(uint16(header.Len() + exchange.Len()))
	tlsRecord := &TLSRecord{
		Type:    []byte{byte(HANDSHAKE)},
		Version: []byte{0x03, 0x01},
		Len:     recordLenByte,
	}

	headerBytes := header.ToByte()
	exchangeBytes := exchange.ToByte()
	t.AddData(headerBytes)
	t.AddData(exchangeBytes)

	var buf bytes.Buffer
	buf.Write(tlsRecord.ToByte())
	buf.Write(headerBytes)
	buf.Write(exchangeBytes)

	return buf.Bytes(), nil
}

func (t *TLSConnect) SendKeyExchange() error {

	bytes, err := t.CreateKeyExchange()
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

type ChangeCipherSpec struct {
}

func (t *TLSConnect) CreateChangeCipherSpec() ([]byte, error) {
	cipherSpecContent := []byte{0x01}

	lenByte := write2byte(uint16(len(cipherSpecContent)))

	tlsRecord := &TLSRecord{
		Type:    []byte{byte(CHANGE_CIPHER_SPEC)},
		Version: []byte{0x03, 0x01},
		Len:     lenByte,
	}

	var buf bytes.Buffer
	buf.Write(tlsRecord.ToByte())
	buf.Write(cipherSpecContent)

	return buf.Bytes(), nil
}

func (t *TLSConnect) SendChangeCipherSpec() error {

	bytes, err := t.CreateChangeCipherSpec()
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

type Finished struct {
	VerifyData []byte
}

func (f *Finished) Len() int {
	return len(f.VerifyData)
}

func (f *Finished) ToByte() []byte {
	return f.VerifyData
}

func NewFinished(master, messages []byte, label string) *Finished {
	return &Finished{
		VerifyData: CreateVerifyData(master, messages, label),
	}
}

//Finishedから暗号化が必要
//AddtionalDataでのTLSHeaderではencryptしてないfinishedのlen16が入るけど
//最終的なTLSHeaderのLenはContentであるencryptedFinishedの40がはいる
func createFinished(t *TLSConnect, writeKey, nonce, messages []byte, label string) ([]byte, error) {
	finished := NewFinished(t.MasterKey, messages, label)
	lenByte := write3byte(uint32(finished.Len()))

	header := &HandShakeHeader{
		Type:   []byte{byte(FINISHED)},
		Length: lenByte,
	}

	message := append(header.ToByte(), finished.ToByte()...)

	t.AddData(message)

	tlsRecord := &TLSRecord{
		Type:    []byte{byte(HANDSHAKE)},
		Version: []byte{0x03, 0x01},
		Len:     write2byte(uint16(len(message))),
	}

	seqNumBytes := Copy(nonce[4:])

	addtionalData := MultiAppend(seqNumBytes, tlsRecord.Type, tlsRecord.Version, tlsRecord.Len)

	gcm, err := GetGCM(writeKey)
	if err != nil {
		return nil, err
	}

	encryptedMessage, err := gcm.EncryptMessage(writeKey, nonce, message, addtionalData)
	if err != nil {
		return nil, err
	}

	tlsRecord.Len = write2byte(uint16(len(nonce[4:]) + len(encryptedMessage)))

	var buf bytes.Buffer
	buf.Write(tlsRecord.ToByte())
	buf.Write(nonce[4:]) //seqNumのこと
	buf.Write(encryptedMessage)

	return buf.Bytes(), nil
}

func (t *TLSConnect) CreateFinished(writeKey, nonce []byte, label string) ([]byte, error) {
	return createFinished(t, writeKey, nonce, HashData(t.Data), label)
}

func (t *TLSConnect) CreateClientFinished() ([]byte, error) {
	copied := Copy(t.KeyBlock.ClientWriteIV)
	nonce := append(copied, t.SeqNumBytes()...)
	return t.CreateFinished(t.KeyBlock.ClientWriteKey, nonce, clientVerifyLabel)
}

func (t *TLSConnect) CreateServerFinished() ([]byte, error) {
	copied := Copy(t.KeyBlock.ServerWriteIV)
	nonce := append(copied, t.SeqNumBytes()...)
	return t.CreateFinished(t.KeyBlock.ServerWriteKey, nonce, serverVerifyLabel)
}

// func (t *TLSConnect) SendFinished(writeKey, nonce []byte, label string) error {

// 	bytes, err := CreateFinished(t, writeKey, nonce, messages, label)
// 	if err != nil {
// 		return err
// 	}

// 	_, err = t.Conn.Write(bytes)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

// func (t *TLSConnect) SendClientFinished() error {
// 	copied := Copy(t.KeyBlock.ClientWriteIV)
// 	nonce := append(copied, t.SeqNumBytes()...)
// 	return t.SendFinished(t.KeyBlock.ClientWriteKey, nonce, clientVerifyLabel)
// }

// func (t *TLSConnect) SendServerFinished() error {
// 	copied := Copy(t.KeyBlock.ServerWriteIV)
// 	nonce := append(copied, t.SeqNumBytes()...)
// 	return t.SendFinished(t.KeyBlock.ServerWriteKey, nonce, serverVerifyLabel)
// }

func (t *TLSConnect) SendClientFirst() error {
	return t.SendHello(CLIENT_HELLO)
}

func (t *TLSConnect) SendServerFirst() error {
	b1, err := t.CreateHello(SERVER_HELLO)
	if err != nil {
		return err
	}
	b2, err := t.CreateCertificate([]string{"../../testData/server.crt"})
	if err != nil {
		return err
	}
	b3, err := t.CreateHelloDone()
	if err != nil {
		return err
	}
	_, err = t.Conn.Write(MultiAppend(b1, b2, b3))
	if err != nil {
		return err
	}

	return nil
}

func (t *TLSConnect) SendClientSecond() error {
	b1, err := t.CreateKeyExchange()
	if err != nil {
		return err
	}
	b2, err := t.CreateChangeCipherSpec()
	if err != nil {
		return err
	}
	b3, err := t.CreateClientFinished()
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(MultiAppend(b1, b2, b3))
	if err != nil {
		return err
	}

	return nil
}

func (t *TLSConnect) SendServerSecond() error {

	b1, err := t.CreateChangeCipherSpec()
	if err != nil {
		return err
	}
	b2, err := t.CreateServerFinished()
	if err != nil {
		return err
	}

	_, err = t.Conn.Write(MultiAppend(b1, b2))
	if err != nil {
		return err
	}

	return nil
}

// handshake_messages All of the data from all messages in this handshake (not including any HelloRequest messages) up to, but not including, this message. This is only data visible at the handshake layer and does not include record layer headers. This is the concatenation of all the Handshake structures as defined in Section 7.4, exchanged thus far.

//とあるので、Dataに使うメッセージはProtocolHeaderを除いた部分(HandShakeならHandShakeのヘッダーも含める)

type TLSOption struct {
	OSPool func() (*x509.CertPool, error)
	Nonce  func(size int) ([]byte, error)
}

func OSPool(fn func() (*x509.CertPool, error)) func(*TLSOption) {
	return func(t *TLSOption) {
		t.OSPool = fn
	}
}

func Nonce(fn func(size int) ([]byte, error)) func(*TLSOption) {
	return func(t *TLSOption) {
		t.Nonce = fn
	}
}

func NewTLSOption(options ...func(*TLSOption)) *TLSOption {
	t := &TLSOption{
		OSPool: defaultOSPool,
		Nonce:  defaultGenerateNonce,
	}

	for _, option := range options {
		option(t)
	}

	return t
}

type TLSConnect struct {
	Conn         net.Conn
	Data         []byte
	ClientRandom []byte
	ServerRandom []byte
	PubKey       *rsa.PublicKey
	Option       *TLSOption
	KeyBlock     *KeyBlock
	MasterKey    []byte
	SeqNum       int
	IsServer     bool
	OverBuffer   *bytes.Buffer
}

func NewTLSConnect(conn net.Conn, option *TLSOption, isServer bool) *TLSConnect {
	return &TLSConnect{
		Conn:       conn,
		Option:     option,
		IsServer:   isServer,
		OverBuffer: bytes.NewBuffer([]byte{}),
	}
}

func (t *TLSConnect) SeqNumBytes() []byte {
	return write8byte(uint64(t.SeqNum))
}

func (t *TLSConnect) AddSeqNum() {
	t.SeqNum++
}

func (t *TLSConnect) AddData(data []byte) {
	t.Data = append(t.Data, data...)
}

func (t *TLSConnect) parseClientHello(content []byte) error {

	h := &Hello{}
	if err := h.ToStruct(content); err != nil {
		return err
	}
	t.ClientRandom = h.Random
	return nil
}
func (t *TLSConnect) parseServerHello(content []byte) error {
	h := &Hello{}
	if err := h.ToStruct(content); err != nil {
		return err
	}
	t.ServerRandom = h.Random
	return nil
}

func (t *TLSConnect) parseCert(content []byte) error {

	c := &Certificate{}
	if err := c.ToStruct(content); err != nil {
		return err
	}
	pubKey, err := c.GetPublicKey(t.Option.OSPool)
	if err != nil {
		return err
	}
	t.PubKey = pubKey

	return nil
}

func (t *TLSConnect) parseClientKeyExchange(content []byte) error {

	c := &ClientKeyExchange{}
	if err := c.ToStruct(content); err != nil {
		return err
	}

	privBytes, err := GetContentFromFIle("../../testData/private.key")
	if err != nil {
		return err
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err != nil {
		return err
	}
	decrypedPreMaster, err := decryptPreMaster(c.PreMasterSecret, privKey)
	if err != nil {
		return err
	}
	//masterとkeyBlockではrandomの順番が逆
	masterKey := CreateMasterKey(decrypedPreMaster, append(t.ClientRandom, t.ServerRandom...))
	t.MasterKey = masterKey
	t.KeyBlock = NewKeyBlock(masterKey, append(t.ServerRandom, t.ClientRandom...))

	return nil
}

func (t *TLSConnect) parseServerHelloDone(content []byte) error {

	return nil
}

func (t *TLSConnect) parseEncryptedFinished(record *TLSRecord, content []byte) error {

	key, implicitNonce := t.KeyBlock.ServerWriteKey, t.KeyBlock.ServerWriteIV
	if t.IsServer {
		key, implicitNonce = t.KeyBlock.ClientWriteKey, t.KeyBlock.ClientWriteIV
	}

	explicitNonce := content[:explicitNonceLen]
	cipherText := content[explicitNonceLen:]
	nonce := append(Copy(implicitNonce), explicitNonce...)

	//addtionalで使うTLSLenはplainFinishedのLenなのでOverHeadを使って求める
	gcm, err := GetGCM(key)
	if err != nil {
		return err
	}

	decryptTLSRecordLen := write2byte(uint16(len(cipherText) - gcm.c.Overhead()))
	addtionalData := MultiAppend(Copy(explicitNonce), record.Type, record.Version, decryptTLSRecordLen)

	decrypted, err := gcm.DecryptedMessage(key, nonce, cipherText, addtionalData)
	if err != nil {
		return err
	}

	return t.parseHandShake(decrypted)
}

func (t *TLSConnect) parseFinished(content []byte) error {

	finished := Finished{
		VerifyData: content,
	}

	label := serverVerifyLabel
	if t.IsServer {
		label = clientVerifyLabel
	}

	verfyData := CreateVerifyData(t.MasterKey, HashData(t.Data), label)

	if !bytes.Equal(finished.VerifyData, verfyData) {
		return ErrFinishedVerify
	}

	return nil
}

func (t *TLSConnect) parseHandShake(bytes []byte) error {
	handShakeType, err := util.Bytes2Int([]byte{bytes[0]})
	if err != nil {
		return err
	}

	content := bytes[4:]

	parse := func() error {
		//10種類あるが今回は下記のみの実装
		switch HandShakeType(handShakeType) {
		case CLIENT_HELLO:
			return t.parseClientHello(content)
		case SERVER_HELLO:
			return t.parseServerHello(content)
		case CERTIFICATE:
			return t.parseCert(content)
		case CLIENT_KEY_EXCHANGE:
			return t.parseClientKeyExchange(content)
		case SERVER_HELLO_DONE:
			return t.parseServerHelloDone(content)
		case FINISHED:
			return t.parseFinished(content)
		default:
			return ErrUnknownHandShake
		}
	}

	if err := parse(); err != nil {
		return err
	}

	//handshakeHeader+handshakeContentをadd
	t.AddData(bytes)
	return nil

}

func (t *TLSConnect) parseTLSRecord(buf []byte) *TLSRecord {
	record := &TLSRecord{
		Type:    []byte{buf[0]},
		Version: buf[1:3],
		Len:     buf[3:5],
	}
	return record

}

func (t *TLSConnect) parseRecvData(buf []byte) error {
	// record := &TLSRecord{
	// 	Type:    []byte{buf[0]},
	// 	Version: buf[1:3],
	// 	Len:     buf[3:5],
	// }
	record := t.parseTLSRecord(buf)

	recType, err := util.Bytes2Int(record.Type)
	if err != nil {
		return err
	}

	contentLen, err := util.Bytes2Int(record.Len)
	if err != nil {
		return err
	}
	contentStart := 5
	contentEnd := contentStart + contentLen

	//overBuf
	overBuf := Copy(buf[contentEnd:])
	t.OverBuffer = bytes.NewBuffer(overBuf)

	switch MessageType(recType) {
	case HANDSHAKE:
		return t.parseHandShake(buf[contentStart:contentEnd])
	case CHANGE_CIPHER_SPEC:
		return nil
	default:
		return nil
		// return record, buf[5:], nil
		// case ALERT:
		// case APPLICATION_DATA:
	}

}

func (t *TLSConnect) ParseEncryptedFinished(buf []byte) error {
	record := t.parseTLSRecord(buf)

	contentLen, err := util.Bytes2Int(record.Len)
	if err != nil {
		return err
	}

	contentStart := 5
	contentEnd := contentStart + contentLen

	//overBuf
	overBuf := Copy(buf[contentEnd:])
	t.OverBuffer = bytes.NewBuffer(overBuf)

	return t.parseEncryptedFinished(record, buf[contentStart:contentEnd])

}

func isChangeCipherSpec(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func (t *TLSConnect) Read(r io.Reader) error {
	// buf := bytes.NewBuffer(nil)
	// io.Copy(buf, r)
	// fmt.Println("copied")
	// var reader io.Reader = io.TeeReader(buf, t.OverBuffer)

	buf, err := GetBufferFromReader(r)
	if err != nil {
		return err
	}

	reader := io.MultiReader(t.OverBuffer, buf)
	for {
		tempBuf := make([]byte, 1500)

		n, err := reader.Read(tempBuf)
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}

		data := tempBuf[:n]

		if isChangeCipherSpec([]byte{data[0]}, []byte{byte(CHANGE_CIPHER_SPEC)}) {
			if err := t.ParseEncryptedFinished(data[6:]); err != nil {
				return err
			}
		} else {
			if err := t.parseRecvData(data); err != nil {
				return err
			}
		}

		if t.OverBuffer.Len() == 0 {
			break
		}

		// reader = io.MultiReader(t.OverBuffer, buf)
		reader = io.MultiReader(t.OverBuffer, buf)

	}

	return nil

}

//overBuffer

// func (t *TLSConnect) Read(buf []byte) error {

// 	var reader io.Reader = t.Conn

// 	if t.OverBuffer.Len() != 0 {
// 		reader = io.MultiReader(t.OverBuffer, t.Conn)
// 	}

// 	n, err := reader.Read(buf)
// 	if err != nil {
// 		return err
// 	}

// 	return t.parseRecvData(buf[:n])

// }
