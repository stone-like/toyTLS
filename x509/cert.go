package x509

import (
	"crypto"
	"crypto/rsa"
	"errors"
)

type Certificate struct {
	TbsCertificate     *TBSCertificate
	SignatureAlgorithm *AlgorithmIdentifier
	SignatureValue     *SignatureValue
}

var (
	ErrUnSupportedAlgorithm = errors.New("This Algorithm Type is not supported")
)

var (
	MD5WithRSAEncryption    = "1.2.840.113549.1.1.4"
	SHA1WithRSAEncryption   = "1.2.840.113549.1.1.5"
	SHA512WithRSAEncryption = "1.2.840.113549.1.1.13"
)

func GetHashType(sigType string) (crypto.Hash, error) {
	switch sigType {
	case SHA512WithRSAEncryption:
		return crypto.SHA512, nil
	}

	return 0, ErrUnSupportedAlgorithm
}

func (c *Certificate) Verify(pubKeyPool []crypto.PublicKey) bool {

	verify := func(pubKey crypto.PublicKey) bool {
		sigValue := c.SignatureValue.Value
		hashType, err := GetHashType(c.SignatureAlgorithm.Algorithm)
		if err != nil {
			return false
		}

		data := c.TbsCertificate.ASN1.Raw

		switch hashType {
		//go本家だと、MD5やSHA1はエラーにしていた
		default:
			h := hashType.New()
			h.Write(data)
			data = h.Sum(nil)
		}

		switch pub := pubKey.(type) {
		case *rsa.PublicKey:
			if err := verifyWithRSA(data, sigValue, pub, hashType); err != nil {
				return false
			}
			return true
		default:
			return false
		}
	}

	for _, pubKey := range pubKeyPool {
		if verify(pubKey) {
			return true
		}
	}

	return false

}

func verifyWithRSA(hashed []byte, sig []byte, key *rsa.PublicKey, hashType crypto.Hash) error {
	return rsa.VerifyPKCS1v15(key, hashType, hashed, sig)
}
