package main

import (
	"fmt"
	"log"
	"net"

	"github.com/stonelike/toytls/tls"
)

func main() {
	ln, err := net.Listen("tcp", ":10443")
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("Client From : %v\n", conn.RemoteAddr())

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	tlsConnect := tls.NewTLSConnect(conn, tls.NewTLSOption())
	b := make([]byte, 1024)
	err := tlsConnect.Read(b)
	if err != nil {
		log.Fatalf("clientHelloError %v\n", err)
	}

	tlsConnect.SendHello(tls.SERVER_HELLO)
	tlsConnect.SendCert([]string{"../../testData/server.crt"})
	tlsConnect.SendHelloDone()

	b = make([]byte, 1024)
	err = tlsConnect.Read(b)
	if err != nil {
		log.Fatalf("clientKeyExchangeError %v\n", err)
	}

	b = make([]byte, 1024)
	err = tlsConnect.Read(b)
	if err != nil {
		log.Fatalf("cipherSpecError %v\n", err)
	}

	fmt.Println(tlsConnect.ClientRandom)
	fmt.Println(tlsConnect.ServerRandom)

}

// func main() {
// 	cert, err := tls.LoadX509KeyPair("../../testData/server.crt", "../../testData/private.key")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	w, _ := os.OpenFile("tls-server.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
// 	// w := os.Stdout

// 	config := &tls.Config{
// 		Certificates: []tls.Certificate{cert},
// 		Rand:         util.ZeroSource{},
// 		MinVersion:   tls.VersionTLS13,
// 		MaxVersion:   tls.VersionTLS13,
// 		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
// 		KeyLogWriter: w,
// 	}
// 	ln, err := tls.Listen("tcp", ":10443", config)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer ln.Close()

// 	for {
// 		conn, err := ln.Accept()
// 		if err != nil {
// 			log.Println(err)
// 			continue
// 		}
// 		log.Printf("Client From : %v\n", conn.RemoteAddr())

// 		go handleConnection(conn)
// 	}
// }

// func handleConnection(conn net.Conn) {
// 	defer conn.Close()
// 	scanner := bufio.NewScanner(conn)
// 	for scanner.Scan() {
// 		msg := scanner.Text()

// 		fmt.Printf("message from client : %s\n", msg)
// 		n, err := conn.Write([]byte("BackToClient\n"))
// 		if err != nil {
// 			log.Println(n, err)
// 			return
// 		}
// 	}
// }
