package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

const masterLabel = "master secret"
const masterLen = 48
const keyBlockLabel = "key expansion"

//keyBlockは暗号によってbyte数が違うが、今回はTLS_RSA_WITH_AES_128_GCM_SHA256を想定しているので40byte
const keyBlockLen = 40

//keyBlockの分割の内訳は下記

//keyblock := KeyBlock{
// 	ClientWriteKey: keyblockbyte[0:16],
// 	ServerWriteKey: keyblockbyte[16:32],
// 	ClientWriteIV:  keyblockbyte[32:36],
// 	ServerWriteIV:  keyblockbyte[36:40],
// }

// master_secret = PRF（pre_master_secret、 "master secret"、ClientHello.random + ServerHello.random）[0..47];

// key_block = PRF（SecurityParameters.master_secret、 "key Expansion"、SecurityParameters.server_random + SecurityParameters.client_random）;

const clientVerifyLabel = "client finished"
const serverVerifyLabel = "server finished"
const verifyLen = 12

//PRF(secret, label, seed) = P_<hash>(secret, label + seed)
func PRF(secret []byte, clientAndServerRandom []byte, label string, length int) []byte {
	return pHash(secret, append([]byte(label), clientAndServerRandom...), length)
}

func pHash(secret, seed []byte, prfLen int) []byte {
	result := make([]byte, prfLen)
	h := hmac.New(sha256.New, secret)
	h.Write(seed)

	a := h.Sum(nil)
	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}

	return result
}

func CreateMasterKey(preMaster []byte, clientAndServerRandom []byte) []byte {
	return PRF(preMaster, clientAndServerRandom, masterLabel, masterLen)
}

type KeyBlock struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

func NewKeyBlock(master []byte, clientAndServerRandom []byte) *KeyBlock {
	keyblockByte := PRF(master, clientAndServerRandom, keyBlockLabel, keyBlockLen)
	return &KeyBlock{
		ClientWriteKey: keyblockByte[:16],
		ServerWriteKey: keyblockByte[16:32],
		ClientWriteIV:  keyblockByte[32:36],
		ServerWriteIV:  keyblockByte[36:40],
	}
}

func CreateVerifyData(master, hashedMessages []byte, label string) []byte {
	return PRF(master, hashedMessages, label, verifyLen)
}

var generateNonce = defaultGenerateNonce

func defaultGenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

var (
	nonceLen         = 12
	implicitNonceLen = 4
	explicitNonceLen = 8
)

// additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length;
// AEADEncrypted = AEAD-Encrypt(write_key, nonce, plaintext, additional_data)
//nonceは暗黙的な部分と明示的な部分に分かれていて、
//暗黙的な部分はclient_write_IVかserver_write_IV
//明示的な部分はseqNum

// nonce = implictNonce + explicitNonce

type GCM struct {
	c cipher.AEAD
}

//gcm.Sealの第一引数は連結させたい元のbyteのため、直接暗号化とは関係ないはず...
func (g *GCM) EncryptMessage(writeKey, nonce, plainText, additionalData []byte) ([]byte, error) {

	cipherText := g.c.Seal(nil, nonce, plainText, additionalData)

	return cipherText, nil
}

func GetGCM(writeKey []byte) (*GCM, error) {
	block, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &GCM{
		c: gcm,
	}, nil

}

func (g *GCM) DecryptedMessage(writeKey, nonce, cipherText, additionalData []byte) ([]byte, error) {
	// block, err := aes.NewCipher(writeKey)
	// if err != nil {
	// 	return nil, err
	// }
	// gcm, err := cipher.NewGCM(block)
	// if err != nil {
	// 	return nil, err
	// }

	plainText, err := g.c.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return nil, err
	}

	return plainText, nil

}

func HashData(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	messages := hasher.Sum(nil)
	return messages
}
