package x509

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

// ASN.1 Distinguished Encoding Rules (DER)
//DERはASN.1記法で書かれたstringやint,OIDをbyteにエンコードするためのルール

// type Certificate struct {
// 	tbsCertificate     TLBCertificate
// 	signatureAlgorithm AlgorithmIdentifier
// 	signatureValue     string
// }

// //optionalなのはポインタで表せばいい？
// type TLBCertificate struct {
// 	//Default Version is v1
// 	Version              *Version
// 	SerialNumber         *CertificateSerialNumber
// 	Signature            *int
// 	Issuer               *string
// 	Validity             *bool
// 	Subject              *string
// 	SubjectPublicKeyInfo *string
// 	IssuerUniqueID       *int
// 	SubjectUniqueID      *int
// 	extensions           *string
// }

// func NewTLBCertificate() *TLBCertificate {
// 	return &TLBCertificate{}
// }

// type Version = int

// //default is v1
// const (
// 	v1 Version = iota
// 	v2
// 	v3
// )

// type CertificateSerialNumber = int

// //証明書の署名にどんなアルゴリズムを使ったか
// //OIDはアルゴリズムのIDみたいなもの、例えばMD5とRSAの組み合わせだったら
// //2A 86 48 86 F7 0D 01 01 04
// //となる
// type OID = []byte
// type AlgorithmIdentifier struct {
// 	Algorithm  *OID
// 	Parameters *int
// }

//goのx509で答え合わせをする
//x509.ParseCertificate(),certicicate.Verify()
// func parseX509() {

// }

var (
	ErrInvalidCertificate             = errors.New("This is not an X509. Wrong Data Type")
	ErrInvalidChildrenLength          = errors.New("Certificate must contain three children")
	ErrInvalidSigValue                = errors.New("Bad SignatureValue. it must be bitString")
	ErrInvalidSigAlgoSeq              = errors.New("Bad AlgorithmIdentifier. it must be sequence")
	ErrInvalidSigAlgoChild            = errors.New("Bad AlgorithmIdentifier. it must contain at most two children")
	ErrInvalidSigAlgoObjIdent         = errors.New("Bad AlgorithmIdentifier. it must start with ObjectIdentifier")
	ErrInvalidTBSCert                 = errors.New("This is not a TBSCertificate,Wrong Data Type")
	ErrInvalidTBSCertChild            = errors.New("Bad TBSCertificate. it must contain at least 6 children")
	ErrInvalidSubjectPublicKey        = errors.New("Bad SubjectPublicKeyInfo. it must be sequence")
	ErrInvalidSubjectPublicKeyChild   = errors.New("Bad SubjectPublicKeyInfo. it must contain two child")
	ErrInvalidKeyValueChild           = errors.New("Bad KeyValue. it must contain two child.modulus and exponent")
	ErrInvalidVersion                 = errors.New("Bad Version. it must 1byte")
	ErrInvalidSigAlgo                 = errors.New("Bad AlgorithmIdentifier. Unsupported Algorithm")
	ErrInvalidNameChild               = errors.New("Bad Name. it must contain six children")
	ErrInvalidNameOID                 = errors.New("Bad Name. it must be valid oid")
	ErrInvalidValidityChild           = errors.New("Bad Validity. it must contain two children")
	ErrInvalidExtensionChild          = errors.New("Bad Extension. it must contain two children")
	ErrInvalidExtension               = errors.New("Bad Extension. Unsupported Extension")
	ErrExtensionCanNotBeCritical      = errors.New("Bad Extension. this extension can not be critical")
	ErrContextSpecific                = errors.New("Bad Class. this class must be Context Specific")
	ErrInvalidOptionalNum             = errors.New("Bad Optional. this optionalNum must be within target struct")
	ErrInvalidBasicConstraintsBoolean = errors.New("Bad BasicConstraints. this requires critical")
)

type DERParser struct {
	Position int
	Data     []byte
}

func NewDERParser(data []byte) *DERParser {
	return &DERParser{
		Data: data,
	}
}

type Data struct {
	Class      int
	Structured bool
	Tag        int
	ByteLength int
	Contents   []byte
	Raw        []byte
}

func (p *DERParser) Reset() {
	p.ResetWithNewData(nil)
}

func (p *DERParser) ResetWithNewData(data []byte) {
	p.Position = 0
	p.Data = data
}

func (p *DERParser) Parse() (*Data, error) {
	class, structured, tag := p.getFirst1byte()
	length := p.getLength()

	byteLength, endNum := p.getByteLengthAndContentEndNum(length)

	return &Data{
		Class:      class,
		Structured: structured,
		Tag:        tag,
		ByteLength: byteLength,
		Contents:   p.Data[p.Position:endNum],
		Raw:        p.Data[:byteLength],
	}, nil
}

func (p *DERParser) getFirst1byte() (class int, structured bool, tag int) {
	class = p.getClass()
	structured = p.getStructured()
	tag = p.getTag()
	p.MovePosition()

	return class, structured, tag
}

//derでは不定長のエンコードはないから気にする必要はあまりないけど
func (p *DERParser) getByteLengthAndContentEndNum(baseLength int) (int, int) {

	//lengthが0x80の時は不定長を表す
	//最後の2byteが00 00となったらEOF
	if baseLength == 0x80 {
		length := 0
		for p.Data[p.Position+length] != 0 || p.Data[p.Position+length+1] != 0 {
			length++
		}
		//+2は最後の00 00の分
		return p.Position + length + 2, p.Position + length
	}

	return p.Position + baseLength, p.Position + baseLength
}

//先頭1byte目から&0xc0で前半2bitを抜き出し、/64で6bit右シフトすると、元の1byte(8bit)から先頭2bitしか残らない
//なので先頭1byteの最初の2bit,つまりクラスを抜き出せる
func (p *DERParser) getClass() int {
	return int((p.Data[p.Position] & 0xc0) / 64)
}

//structuredは先頭1byteの5bit目にある、なので0x20で5bit目だけ抜き出してビットが立ってるかは == すればいい
func (p *DERParser) getStructured() bool {
	return (p.Data[p.Position] & 0x20) == 0x20
}

//tagは先頭1byte目の4~0bit
//tagは可変長のとき全部11111となっている
func (p *DERParser) getTag() int {

	//タグが11111ではないとき
	if p.Data[p.Position]&0x1f != 0x1f {
		return int(p.Data[p.Position] & 0x1f)
	}

	p.MovePosition()
	tag := 0
	for p.Data[p.Position] >= 0x80 {
		tag = int(byte(tag*128) + p.Data[p.Position] - 0x80)
		p.MovePosition()
	}

	tag = int(byte(tag*128) + p.Data[p.Position] - 0x80)

	return int(tag)
}

//tagを読み終わったらlen
//lenも可変長で、可変長の時は先頭1bit目が立っている
//先頭1bit目が立っていれば必ず0x80以上になるのでそこをチェックしてあげる
func (p *DERParser) getLength() int {

	//0x80以下の時(0x80でもそのまま返す)
	if p.Data[p.Position] <= 0x80 {
		length := p.Data[p.Position]
		p.MovePosition()
		return int(length)
	}

	//続きの何byteが長さを表しているか
	byteNum := int(p.Data[p.Position] & 0x7f)
	p.MovePosition()

	length := 0
	//例えばbyteNum=2で、次の2byteが02 10だったら
	// 2 * 256 + 16と計算する
	for i := 0; i < byteNum; i++ {
		length = length*256 + int(p.Data[p.Position])
		p.MovePosition()
	}

	return length

}

func (p *DERParser) MovePosition() {
	p.Position++
}

type CertParser struct {
	// Position  int
	ASN1      *Data
	DERParser *DERParser
}

func NewCertParser(data []byte) *CertParser {
	return &CertParser{
		DERParser: NewDERParser(data),
	}
}

type AlgorithmIdentifier struct {
	Algorithm  string
	Parameters *Parameters //Optional
}

type Parameters struct {
}

// type SignatureValue struct {
// 	ASN1 *Data
// 	Bits *BitString
// }
type SignatureValue struct {
	Value []byte
}

func (s *SignatureValue) ToHex() string {
	return parseHex(s.Value)
}

type BitString struct {
	UnUsedBits int
	Bytes      []byte
}

// type SubjectPublicKeyInfo struct {
// 	ASN1             *Data
// 	Algorithm        *AlgorithmIdentifier
// 	SubjectPublicKey *BitString
// }

type SubjectPublicKeyInfo struct {
	Algorithm        *AlgorithmIdentifier
	SubjectPublicKey *SubjectPublicKey
}

type SubjectPublicKey struct {
	Modulus  string
	Exponent string //displayではint
}

func (s *SubjectPublicKey) toPubKey() (crypto.PublicKey, error) {

	i := new(big.Int)
	i.SetString(s.Modulus, 16)
	e, err := strconv.ParseInt(s.Exponent, 16, 64)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: i,
		E: int(e),
	}, nil
}

func (s *SubjectPublicKeyInfo) displayAlgorithm() {
	// fmt.Printf("    Public Key Algorithm: %s\n", s.Algorithm)
}

func (s *SubjectPublicKeyInfo) displayModulus() {

}

func (s *SubjectPublicKeyInfo) Display() {
	fmt.Println("Subject Public Key Info:")
	s.displayAlgorithm()
	fmt.Println("        Modulus")
	s.displayModulus()

}

func (p *CertParser) Parse() (*Certificate, error) {
	asn1, err := p.DERParser.Parse()
	if err != nil {
		return nil, err
	}

	if asn1.Class != 0 || asn1.Tag != 16 || !asn1.Structured {
		return nil, ErrInvalidCertificate
	}

	p.DERParser.Reset()

	p.ASN1 = asn1
	pieces, err := p.parseDERList(p.ASN1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) != 3 {
		return nil, ErrInvalidChildrenLength
	}

	tbsCert, err := p.parseTBSCertificate(pieces[0])
	if err != nil {
		return nil, err
	}
	sigAlgo, err := p.parseAlgorithmIdentifier(pieces[1])
	if err != nil {
		return nil, err
	}
	sigVal, err := p.parseSignatureValue(pieces[2])
	if err != nil {
		return nil, err
	}

	return &Certificate{
		TbsCertificate:     tbsCert,
		SignatureAlgorithm: sigAlgo,
		SignatureValue:     sigVal,
	}, nil
}

//SEQUENCEのネスト部分をパースしていく
func (p *CertParser) parseDERList(contents []byte) ([]*Data, error) {

	var result []*Data
	nextPosition := 0
	for nextPosition < len(contents) {
		p.DERParser.ResetWithNewData(contents[nextPosition:])
		nextPiece, err := p.DERParser.Parse()
		if err != nil {
			return nil, err
		}
		result = append(result, nextPiece)
		nextPosition += nextPiece.ByteLength
	}

	p.DERParser.Reset()

	return result, nil
}

type TBSCertificate struct {
	ASN1                 *Data
	Version              int
	SerialNumber         string
	Signature            *AlgorithmIdentifier
	Issuer               *Name
	Validity             *VerifyPeriod
	Subject              *Name
	SubjectPublicKeyInfo *SubjectPublicKeyInfo
	IssuerUniqueID       *int        //Optional
	SubjectUniqueID      *int        //Optional
	Extensions           []Extension //Optional
}

type Name struct {
	Country          string
	StateOrProvince  string
	Locality         string
	Organization     string
	OrganizationUnit string
	Common           string
}

type VerifyPeriod struct {
	NotBefore time.Time
	NotAfter  time.Time
}

var layout = "Jan 02 15:04:05 2006 GMT"

func (v *VerifyPeriod) Display() {

	fmt.Println("Validity")
	fmt.Printf("    Not Before: %s\n", v.NotBefore.Format(layout))
	fmt.Printf("    Not After : %s\n", v.NotAfter.Format(layout))
}

type IssuerUniqueID int
type SubjectUniqueID int

//TODO curPieceNumではなくてDERParserでASN1をデータごとに繋げていく
func (p *CertParser) parseTBSCertificate(asn1 *Data) (*TBSCertificate, error) {
	if asn1.Class != 0 || asn1.Tag != 16 || !asn1.Structured {
		return nil, ErrInvalidCertificate
	}

	tbs := &TBSCertificate{
		ASN1: asn1,
	}
	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	//versionを除いて最低6個は子供がいないといけない(versionはないときもある)
	if len(pieces) < 6 {
		return nil, ErrInvalidTBSCertChild
	}

	curPieceNum := 0
	versionExists := false

	tbs.Version, versionExists, err = p.parseVersion(pieces[curPieceNum])
	if err != nil {
		return nil, err
	}

	if versionExists {
		curPieceNum = 1
	}

	tbs.SerialNumber = p.parseToHex(pieces[curPieceNum])
	tbs.Signature, err = p.parseAlgorithmIdentifier(pieces[curPieceNum+1])
	if err != nil {
		return nil, err
	}
	tbs.Issuer, err = p.parseName(pieces[curPieceNum+2])
	if err != nil {
		return nil, err
	}
	tbs.Validity, err = p.parseValidity(pieces[curPieceNum+3])
	if err != nil {
		return nil, err
	}
	tbs.Subject, err = p.parseName(pieces[curPieceNum+4])
	if err != nil {
		return nil, err
	}
	tbs.SubjectPublicKeyInfo, err = p.parseSubjectPublicKeyInfo(pieces[curPieceNum+5])
	if err != nil {
		return nil, err
	}

	err = p.parseOptional(pieces[curPieceNum+6:], tbs)
	if err != nil {
		return nil, err
	}

	return tbs, nil

}

// TBSCertificate  ::=  SEQUENCE  {
// 	version         [0]  Version DEFAULT v1,
// 	serialNumber         CertificateSerialNumber,
// 	signature            AlgorithmIdentifier,
// 	issuer               Name,
// 	validity             Validity,
// 	subject              Name,
// 	subjectPublicKeyInfo SubjectPublicKeyInfo,
// 	issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
// 						 -- If present, version MUST be v2 or v3
// 	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
// 						 -- If present, version MUST be v2 or v3
// 	extensions      [3]  Extensions OPTIONAL
// 						 -- If present, version MUST be v3 --  }
//となっているので、1だったらissuer,2だったらsubject,3だったらextensions
func (p *CertParser) parseOptional(data []*Data, tbs *TBSCertificate) error {
	//ここもdataを回してoptionのTagごとに分岐
	for _, d := range data {
		if d.Class != ASN1_CONTEXT_SPECIFIC {
			return ErrContextSpecific
		}
		switch d.Tag {
		case 1:
			continue
		case 2:
			continue
		case 3:
			extensions, err := p.parseExtensions(data[0])
			if err != nil {
				return err
			}
			tbs.Extensions = extensions
		default:
			return ErrInvalidOptionalNum
		}

	}

	return nil
}

//Extensions
// Extension(byte数)
//  Extension(このExtensionのbyte数)
//   Extension名
//   Content
func (p *CertParser) parseExtensions(asn1 *Data) ([]Extension, error) {
	p.DERParser.ResetWithNewData(asn1.Contents)
	extensionsData, err := p.DERParser.Parse()
	if err != nil {
		return nil, err
	}
	pieces, err := p.parseDERList(extensionsData.Contents)
	if err != nil {
		return nil, err
	}
	extensionLen := len(pieces)

	extensions := make([]Extension, extensionLen)

	for i := 0; i < extensionLen; i++ {
		extension, err := p.parseExtension(pieces[i])
		if err != nil {
			return nil, err
		}
		extensions[i] = extension
	}

	return extensions, nil
}

//  Extension(このExtensionのbyte数)
//   Extension名
//   Critical(Option)
//   Content
//上記部分のParse
func (p *CertParser) parseExtension(asn1 *Data) (Extension, error) {
	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) != 2 && len(pieces) != 3 {
		return nil, ErrInvalidExtensionChild
	}

	oid := p.parseObjectIdent(pieces[0].Contents)

	switch oid {
	case oid_subjectKeyIdentifier:
		return p.parseSubjectKeyIdentifier(pieces[1:], oid)
	case oid_authorityKeyIdentifier:
		return p.parseAuthorityKeyIdentifier(pieces[1:], oid)
	case oid_basicConstraints:
		return p.parseBasicConstraints(pieces[1:], oid)
	default:
		return nil, ErrInvalidExtension
	}

}

//doesn't have critical
// SubjectKeyIdentifier ::= KeyIdentifier
func (p *CertParser) parseSubjectKeyIdentifier(data []*Data, oid string) (*SubjectKeyIdentifier, error) {
	if len(data) == 2 {
		return nil, ErrExtensionCanNotBeCritical
	}

	p.DERParser.ResetWithNewData(data[0].Contents)
	keyIdent, err := p.DERParser.Parse()
	if err != nil {
		return nil, err
	}

	return &SubjectKeyIdentifier{
		OID:           oid,
		KeyIdentidier: p.parseToHex(keyIdent),
	}, nil
}

//doesn't have critical
// AuthorityKeyIdentifier ::= SEQUENCE {
//     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
//     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
//     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }

//optionalの場合、クラスにはコンテキスト特定クラスが使用され、tagは普通の奴ではなく構造体の上からの番号になる
//例えばkeyIdentifierだったらclass=2(コンテキスト特定クラス),tag=0となる
//authorityCertIssuerだったらtag=1
func (p *CertParser) parseAuthorityKeyIdentifier(data []*Data, oid string) (*AuthorityKeyIdentifier, error) {
	if len(data) == 2 {
		return nil, ErrExtensionCanNotBeCritical
	}

	p.DERParser.ResetWithNewData(data[0].Contents)
	seq, err := p.DERParser.Parse()
	if err != nil {
		return nil, err
	}

	pieces, err := p.parseDERList(seq.Contents)
	if err != nil {
		return nil, err
	}

	ident := &AuthorityKeyIdentifier{
		OID: oid,
	}

	for _, piece := range pieces {

		if piece.Class != ASN1_CONTEXT_SPECIFIC {
			return nil, ErrContextSpecific
		}

		switch piece.Tag {
		case 0:
			hex := p.parseToHex(piece)
			ident.KeyIdentifier = &hex
		case 1:
			name, err := p.parseName(piece)
			if err != nil {
				return nil, err
			}
			ident.AuthorityCertIssuer = name
		case 2:
			hex := p.parseToHex(piece)
			ident.AuthorityKeyIdentifier = &hex
		default:
			return nil, ErrInvalidOptionalNum
		}
	}

	return ident, nil
}

//may have critical
//BasicConstraints ::= SEQUENCE {
//    cA                   BOOLEAN DEFAULT FALSE,
//   pathLenConstraint    INTEGER (0..MAX) OPTIONAL
//}
func (p *CertParser) parseBasicConstraints(data []*Data, oid string) (*BasicConstraints, error) {

	critical := false
	component := data[0]
	if len(data) == 2 {
		var err error
		critical, err = p.parseBoolean(component)
		if err != nil {
			return nil, err
		}
		component = data[1]
	}

	basicConstraints := &BasicConstraints{OID: oid, Critical: critical}

	p.DERParser.ResetWithNewData(component.Contents)
	seq, err := p.DERParser.Parse()
	if err != nil {
		return nil, err
	}

	pieces, err := p.parseDERList(seq.Contents)
	if err != nil {
		return nil, err
	}

	for _, d := range pieces {
		switch d.Tag {
		case ASN1_INTEGER:
			i, err := Bytes2Int(d.Contents)
			if err != nil {
				return nil, err
			}
			basicConstraints.PathLenConstraint = &i
		case ASN1_BOOLEAN:
			isCA, err := p.parseBoolean(d)
			if err != nil {
				return nil, err
			}
			basicConstraints.CA = isCA
		default:
			return nil, ErrInvalidOptionalNum
		}
	}

	return basicConstraints, nil
}

func (p *CertParser) parseBoolean(asn1 *Data) (bool, error) {
	if asn1.Tag != ASN1_BOOLEAN {
		return false, ErrInvalidBasicConstraintsBoolean
	}

	i, err := Bytes2Int(asn1.Contents)
	if err != nil {
		return false, err
	}

	if i == 0 {
		return false, nil
	}

	return true, nil

}

func (p *CertParser) parseVersion(asn1 *Data) (int, bool, error) {
	if asn1.Tag != 0 || asn1.Class != ASN1_CONTEXT_SPECIFIC {
		return 1, false, nil

	}

	p.DERParser.ResetWithNewData(asn1.Contents)

	version, err := p.DERParser.Parse()
	if err != nil {
		return 1, false, err
	}
	p.DERParser.Reset()

	//expect version.Content is only 1byte
	if len(version.Contents) != 1 {
		return 1, false, ErrInvalidVersion
	}

	versionNum, err := Bytes2Int(version.Contents)
	if err != nil {
		return 1, false, err
	}

	return versionNum + 1, true, nil
}

func parseHex(b []byte) string {
	return hex.EncodeToString(b)
}

func (p *CertParser) parseToHex(asn1 *Data) string {
	return parseHex(asn1.Contents)
}

//Nameは6つchildがあり、それぞれのchildは
//SetOF
// AttributeTypeAndValue
//  oid
//  content
//となっているのでchildをgetしたあと、もう一度DERParseがいる
var (
	OID_CommonName             []byte = []byte{0x55, 0x04, 0x03}
	OID_CountryName            []byte = []byte{0x55, 0x04, 0x06}
	OID_LocalityName           []byte = []byte{0x55, 0x04, 0x07}
	OID_StateOrProvinceName    []byte = []byte{0x55, 0x04, 0x08}
	OID_OrganizationName       []byte = []byte{0x55, 0x04, 0x0A}
	OID_OrganizationalUnitName []byte = []byte{0x55, 0x04, 0x0B}

	OIDNames [][]byte = [][]byte{OID_CommonName, OID_CountryName, OID_LocalityName, OID_StateOrProvinceName, OID_OrganizationName, OID_OrganizationalUnitName}
)

func (p *CertParser) getNameChildContent(childRoot *Data) (string, error) {

	p.DERParser.ResetWithNewData(childRoot.Contents)
	attr, err := p.DERParser.Parse()
	if err != nil {
		return "", err
	}

	checkOID := func(oid []byte) bool {
		for _, name := range OIDNames {
			if bytes.Equal(oid, name) {
				return true
			}
		}
		return false
	}

	oidRawdata := attr.Contents[:5]
	p.DERParser.ResetWithNewData(oidRawdata)
	oid, err := p.DERParser.Parse()
	if err != nil {
		return "", err
	}
	if !checkOID(oid.Contents) {
		return "", ErrInvalidNameOID
	}
	contentRawData := attr.Contents[5:]
	p.DERParser.ResetWithNewData(contentRawData)
	content, err := p.DERParser.Parse()
	if err != nil {
		return "", err
	}

	p.DERParser.Reset()

	return string(content.Contents), nil
}
func (p *CertParser) parseName(asn1 *Data) (*Name, error) {

	piece, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(piece) != 6 {
		return nil, ErrInvalidNameChild
	}

	country, err := p.getNameChildContent(piece[0])
	if err != nil {
		return nil, err
	}

	stateOrProvince, err := p.getNameChildContent(piece[1])
	if err != nil {
		return nil, err
	}
	locality, err := p.getNameChildContent(piece[2])
	if err != nil {
		return nil, err
	}

	organization, err := p.getNameChildContent(piece[3])
	if err != nil {
		return nil, err
	}

	organizationUnit, err := p.getNameChildContent(piece[4])
	if err != nil {
		return nil, err
	}
	common, err := p.getNameChildContent(piece[5])
	if err != nil {
		return nil, err
	}

	p.DERParser.Reset()

	return &Name{
		Country:          country,
		StateOrProvince:  stateOrProvince,
		Locality:         locality,
		Organization:     organization,
		OrganizationUnit: organizationUnit,
		Common:           common,
	}, nil
}

func (p *CertParser) parseValidity(asn1 *Data) (*VerifyPeriod, error) {
	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) != 2 {
		return nil, ErrInvalidValidityChild
	}

	toTime := func(b []byte) (time.Time, error) {
		data := string(b)
		year, err := strconv.Atoi(data[:2])
		if err != nil {
			return time.Time{}, err
		}
		year += 2000

		month, err := strconv.Atoi(data[2:4])
		if err != nil {
			return time.Time{}, err
		}
		day, err := strconv.Atoi(data[4:6])
		if err != nil {
			return time.Time{}, err
		}
		hour, err := strconv.Atoi(data[6:8])
		if err != nil {
			return time.Time{}, err
		}
		minute, err := strconv.Atoi(data[8:10])
		if err != nil {
			return time.Time{}, err
		}
		sec, err := strconv.Atoi(data[10:12])
		if err != nil {
			return time.Time{}, err
		}
		gmt, err := time.LoadLocation("GMT")
		if err != nil {
			return time.Time{}, err
		}

		return time.Date(
			year,
			time.Month(month),
			day,
			hour,
			minute,
			sec,
			0,
			gmt,
		), nil
	}
	notBefore, err := toTime(pieces[0].Contents)
	if err != nil {
		return nil, err
	}
	notAfter, err := toTime(pieces[1].Contents)
	if err != nil {
		return nil, err
	}

	return &VerifyPeriod{
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, nil
}

var (
	OID_RSA = "1.2.840.113549.1.1.1"

	ValidAlgos = []string{OID_RSA}
)

func (p *CertParser) parseSubjectPublicKeyInfo(asn1 *Data) (*SubjectPublicKeyInfo, error) {
	if asn1.Class != 0 || asn1.Tag != 16 || !asn1.Structured {
		return nil, ErrInvalidSubjectPublicKey
	}

	pubKey := &SubjectPublicKeyInfo{}
	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) != 2 {
		return nil, ErrInvalidSubjectPublicKeyChild
	}

	checkAlgo := func(str string) bool {
		for _, algo := range ValidAlgos {
			if str == algo {
				return true
			}
		}
		return false
	}

	algorithm, err := p.parseAlgorithmIdentifier(pieces[0])
	if err != nil {
		return nil, err
	}

	if !checkAlgo(algorithm.Algorithm) {
		return nil, ErrInvalidSigAlgo
	}

	subjectPublicKey := p.parseBitString(pieces[1].Contents)

	//subjectPublicKeyの中身のmodulesとexponentを取り出す
	p.DERParser.ResetWithNewData(subjectPublicKey.Bytes)
	keyValueData, err := p.DERParser.Parse()
	if err != nil {
		return nil, err
	}
	pieces, err = p.parseDERList(keyValueData.Contents)
	if err != nil {
		return nil, err
	}
	if len(pieces) != 2 {
		return nil, ErrInvalidKeyValueChild
	}

	modulus := p.parseToHex(pieces[0])
	exponent := p.parseToHex(pieces[1])

	pubKey.Algorithm = algorithm
	pubKey.SubjectPublicKey = &SubjectPublicKey{
		Modulus:  modulus,
		Exponent: exponent,
	}

	return pubKey, nil
}

func (p *CertParser) parseAlgorithmIdentifier(asn1 *Data) (*AlgorithmIdentifier, error) {
	if asn1.Class != 0 || asn1.Tag != 16 || !asn1.Structured {
		return nil, ErrInvalidSigAlgoSeq
	}

	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) > 2 {
		return nil, ErrInvalidSigAlgoChild
	}

	encodeAlgo := pieces[0]
	if encodeAlgo.Class != 0 || encodeAlgo.Tag != 6 || encodeAlgo.Structured {
		return nil, ErrInvalidSigAlgoObjIdent
	}

	algIdent := &AlgorithmIdentifier{}

	algIdent.Algorithm = p.parseObjectIdent(encodeAlgo.Contents)

	//parameters is optional
	//TODO patameters部分も実装する
	if len(pieces) == 2 {
		algIdent.Parameters = &Parameters{}
	}

	return algIdent, nil

}

//encodeの規則
//2.999.3を例として、
//最初の二つは一つにエンコードされる->40*X+Y
//今回の例だったら40*2+999 = 1073
//そして、各要素ごとに下記の処理を行う

//複数byteで表す場合
//複数byteで表した上で最後の1byte以外の8bit目を1にする

//単一byte
//そのまま

//下記はOIDのdecodeだからencodeの逆を行う

//正直decodeせずに目標とするOIDはわかっているから、それをbytes.Equalする方が早い気もする
func decodeOID(data []byte) string {
	var builder strings.Builder
	//最初の二つを取り出す
	first := int(math.Floor(float64(data[0]) / float64(40)))
	second := int(data[0] % 40)
	builder.WriteString(strconv.Itoa(first))
	builder.WriteString(".")
	builder.WriteString(strconv.Itoa(second))

	position := 1
	for position < len(data) {
		nextInteger := 0
		//最後のbyte以外はビット8が1になっているはずなので
		for data[position] >= 0x80 {
			//0x80で1byte(8bit)右にシフト
			nextInteger = nextInteger*int(0x80) + int((data[position] & 0x7f))
			position++
		}

		nextInteger = nextInteger*int(0x80) + int(data[position])
		position++
		builder.WriteString(".")
		builder.WriteString(strconv.Itoa(nextInteger))
	}

	return builder.String()
}

// var (
// 	oidForMD5WithRSA []byte = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04}
// 	oidForSHAWithRSA []byte = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05}
// )

func (p *CertParser) parseObjectIdent(data []byte) string {
	return decodeOID(data)
}
func (p *CertParser) parseSignatureValue(asn1 *Data) (*SignatureValue, error) {
	if asn1.Class != 0 || asn1.Tag != 3 || asn1.Structured {
		return nil, ErrInvalidSigValue
	}

	sig := &SignatureValue{}

	bits := p.parseBitString(asn1.Contents)
	sig.Value = bits.Bytes

	return sig, nil
}

func (p *CertParser) parseBitString(data []byte) *BitString {
	return &BitString{
		UnUsedBits: int(data[0]),
		Bytes:      data[1:],
	}
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

func (c *Certificate) ShowDetail() {
	//show detail...
}
