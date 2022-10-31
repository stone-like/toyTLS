package main

import (
	"crypto/x509"
	"fmt"
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

	fmt.Println(tlsConnect.ClientRandom)
	fmt.Println(tlsConnect.ServerRandom)

}

// func main() {
// 	w, _ := os.OpenFile("tls-client.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

// 	// caCertPool := x509.NewCertPool()
// 	cert, err := tls.LoadX509KeyPair("../../testData/server.crt", "../../testData/private.key")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// x509cert, err := x509.ParseCertificate(cert.Certificate[0])
// 	// if err != nil {
// 	// 	log.Fatal(err)
// 	// }
// 	// caCertPool.AddCert(x509cert)

// 	// w := os.Stdout
// 	config := &tls.Config{
// 		Certificates: []tls.Certificate{cert},
// 		MinVersion:   tls.VersionTLS13,
// 		MaxVersion:   tls.VersionTLS13,
// 		Rand:         util.ZeroSource{},
// 		KeyLogWriter: w,
// 		// 楕円曲線のタイプをP256に設定
// 		// CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveID(tls2.X25519)},
// 		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
// 		InsecureSkipVerify: true,
// 		// RootCAs:      caCertPool,
// 		//CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
// 	}
// 	conn, err := tls.Dial("tcp", "127.0.0.1:10443", config)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer conn.Close()

// 	req, _ := hex.DecodeString("474554202f20485454502f312e310d0a486f73743a203132372e302e302e313a31303434330d0a557365722d4167656e743a206375726c2f372e36382e300d0a4163636570743a202a2f2a0d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a")
// 	//n, err := conn.Write([]byte("hello\n"))
// 	n, err := conn.Write(req)
// 	//n, err := conn.Write(req)
// 	if err != nil {
// 		log.Println(n, err)
// 		return
// 	}

// 	buf := make([]byte, 500)
// 	n, err = conn.Read(buf)
// 	if err != nil {
// 		log.Println(n, err)
// 		return
// 	}

// 	fmt.Printf("message from server : %s\n", string(buf[:n]))

// }
