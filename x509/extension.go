package x509

//とりあえずオレオレ証明書作ったときに出てきたこの三つだけExtensionは取り扱う
var (
	oid_subjectKeyIdentifier   = "2.5.29.14"
	oid_authorityKeyIdentifier = "2.5.29.35"
	oid_basicConstraints       = "2.5.29.19"
)

type Extension interface {
	Display()
	GetOid() string
}

type AuthorityKeyIdentifier struct {
	OID                    string
	KeyIdentifier          *string //optional
	AuthorityCertIssuer    *Name   //optional
	AuthorityKeyIdentifier *string //optional
}

func (a *AuthorityKeyIdentifier) Display() {

}

func (a *AuthorityKeyIdentifier) GetOid() string {
	return a.OID
}

type SubjectKeyIdentifier struct {
	OID           string
	KeyIdentidier string
}

func (s *SubjectKeyIdentifier) Display() {

}

func (s *SubjectKeyIdentifier) GetOid() string {
	return s.OID
}

type BasicConstraints struct {
	OID               string
	Critical          bool
	CA                bool
	PathLenConstraint *int
}

func (b *BasicConstraints) Display() {

}

func (b *BasicConstraints) GetOid() string {
	return b.OID
}
