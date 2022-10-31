package main

import (
	"crypto/x509"
	"log"
	"net"

	"github.com/stonelike/toytls/tls"
)

func main() {
	conn, err := net.Dial("tcp", ":10443")
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()

	certByte, err := tls.GetContentFromFIle("../../testData/server.crt")
	if err != nil {
		log.Fatalln(err)
	}

	cert, err := x509.ParseCertificate(certByte)
	if err != nil {
		log.Fatalln(err)
	}

	option := tls.NewTLSOption()

	osFn := func() (*x509.CertPool, error) {
		pool, err := option.OSPool()
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
		return pool, nil
	}
	tlsConnect := tls.NewTLSConnect(conn, tls.NewTLSOption(tls.OSPool(osFn)), false)

	if err := tlsConnect.SendClientFirst(); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.Read(tlsConnect.Conn); err != nil {
		log.Fatalf("error:%v\n", err)
	}
	if err := tlsConnect.SendClientSecond(); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.Read(tlsConnect.Conn); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.SendApplicationData([]byte("Hello server!")); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.Read(tlsConnect.Conn); err != nil {
		log.Fatalf("error:%v\n", err)
	}

}
