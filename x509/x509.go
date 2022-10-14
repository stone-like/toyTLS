package x509

import (
	"bufio"
	"encoding/base64"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
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
	ErrInvalidCertificate           = errors.New("This is not an X509. Wrong Data Type")
	ErrInvalidChildrenLength        = errors.New("Certificate must contain three children")
	ErrInvalidSigValue              = errors.New("Bad SignatureValue. it must be bitString")
	ErrInvalidSigAlgoSeq            = errors.New("Bad AlgorithmIdentifier. it must be sequence")
	ErrInvalidSigAlgoChild          = errors.New("Bad AlgorithmIdentifier. it must contain at most two children")
	ErrInvalidSigAlgoObjIdent       = errors.New("Bad AlgorithmIdentifier. it must start with ObjectIdentifier")
	ErrInvalidTBSCert               = errors.New("This is not a TBSCertificate,Wrong Data Type")
	ErrInvalidTBSCertChild          = errors.New("Bad TBSCertificate. it must contain at least 7 children")
	ErrInvalidSubjectPublicKey      = errors.New("Bad SubjectPublicKeyInfo. it must be sequence")
	ErrInvalidSubjectPublicKeyChild = errors.New("Bad SubjectPublicKeyInfo. it must contain two child")
)

func parseAST2DER() {}

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

//先頭1byte目から&0xc0で前半4bitを抜き出し、/64で6bit右シフトすると、元の1byte(8bit)から先頭2bitしか残らない
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
	Position  int
	ASN1      *Data
	DERParser *DERParser
}

func NewCertParser(data []byte) *CertParser {
	return &CertParser{
		DERParser: NewDERParser(data),
	}
}

type Certificate struct {
	TbsCertificate     *TBSCertificate
	SignatureAlgorithm *AlgorithmIdentifier
	SignatureValue     *SignatureValue
}

// func (c *Certificate) ExtractPublicKey() []byte {

// }

type AlgorithmIdentifier struct {
	ASN1       *Data
	Algorithm  string
	Parameters *Parameters //Optional
}

type Parameters struct {
	ASN1 *Data
}

type SignatureValue struct {
	ASN1 *Data
	Bits *BitString
}

type BitString struct {
	UnUsedBits int
	Bytes      []byte
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
	Vertion              *Data
	SerialNumber         *Data
	Signature            *AlgorithmIdentifier
	Issuer               *Data
	Validity             *Data
	Subject              *Data
	SubjectPublicKeyInfo *SubjectPublicKeyInfo
	IssuerUniqueID       *IssuerUniqueID  //Optional
	SubjectUniqueID      *SubjectUniqueID //Optional
	Extensions           *Extensions      //Optional

}

type IssuerUniqueID int
type SubjectUniqueID int
type Extensions struct {
}
type SubjectPublicKeyInfo struct {
	ASN1             *Data
	Algorithm        *AlgorithmIdentifier
	SubjectPublicKey *BitString
}

func (p *CertParser) parseTBSCertificate(asn1 *Data) (*TBSCertificate, error) {
	if asn1.Class != 0 || asn1.Tag != 16 || !asn1.Structured {
		return nil, ErrInvalidCertificate
	}

	tbs := &TBSCertificate{ASN1: asn1}
	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) < 7 {
		return nil, ErrInvalidTBSCertChild
	}

	tbs.Vertion = pieces[0]
	tbs.SerialNumber = pieces[1]
	tbs.Signature, err = p.parseAlgorithmIdentifier(pieces[2])
	if err != nil {
		return nil, err
	}
	tbs.Issuer = pieces[3]
	tbs.Validity = pieces[4]
	tbs.Subject = pieces[5]
	tbs.SubjectPublicKeyInfo, err = p.parseSubjectPublicKeyInfo(pieces[6])
	if err != nil {
		return nil, err
	}

	//ignoreOptionFieldForNow
	return tbs, nil

}

func (p *CertParser) parseSubjectPublicKeyInfo(asn1 *Data) (*SubjectPublicKeyInfo, error) {
	if asn1.Class != 0 || asn1.Tag != 16 || !asn1.Structured {
		return nil, ErrInvalidSubjectPublicKey
	}

	pubKey := &SubjectPublicKeyInfo{ASN1: asn1}
	pieces, err := p.parseDERList(asn1.Contents)
	if err != nil {
		return nil, err
	}

	if len(pieces) != 2 {
		return nil, ErrInvalidSubjectPublicKeyChild
	}

	pubKey.Algorithm, err = p.parseAlgorithmIdentifier(pieces[0])
	if err != nil {
		return nil, err
	}
	pubKey.SubjectPublicKey = p.parseBitString(pieces[1].Contents)

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

	algIdent := &AlgorithmIdentifier{
		ASN1: asn1,
	}

	algIdent.Algorithm = p.parseObjectIdent(encodeAlgo.Contents)

	//parameters is optional
	if len(pieces) == 2 {
		algIdent.Parameters = &Parameters{
			ASN1: pieces[1],
		}
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
func (p *CertParser) parseObjectIdent(data []byte) string {
	return decodeOID(data)
}
func (p *CertParser) parseSignatureValue(asn1 *Data) (*SignatureValue, error) {
	if asn1.Class != 0 || asn1.Tag != 3 || asn1.Structured {
		return nil, ErrInvalidSigValue
	}

	sig := &SignatureValue{
		ASN1: asn1,
	}

	sig.Bits = p.parseBitString(asn1.Contents)

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
