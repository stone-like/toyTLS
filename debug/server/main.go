package main

import (
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
	tlsConnect := tls.NewTLSConnect(conn, tls.NewTLSOption(), true)
	if err := tlsConnect.Read(tlsConnect.Conn); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.SendServerFirst(); err != nil {
		log.Fatalf("error:%v\n", err)
	}
	if err := tlsConnect.Read(tlsConnect.Conn); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.SendServerSecond(); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.Read(tlsConnect.Conn); err != nil {
		log.Fatalf("error:%v\n", err)
	}

	if err := tlsConnect.SendApplicationData([]byte("Hello client!")); err != nil {
		log.Fatalf("error:%v\n", err)
	}

}
