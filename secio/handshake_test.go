package secio

import (
	"bytes"
	"net"
	"testing"
)

func TestHandshake(t *testing.T) {
	dataChan := make(chan []byte)
	data := []byte("hello world")
	addrChan := make(chan net.Addr)

	go func() {
		key := GenerateSecp256k1()
		config := NewConfig(key)
		listener, _ := net.Listen("tcp", ":0")
		addrChan <- listener.Addr()
		defer listener.Close()
		conn, _ := listener.Accept()
		sec, err := config.Handshake(conn)
		if err != nil {
			panic(err)
		}
		recv := make([]byte, 11)
		sec.Read(recv)
		sec.Write(recv)
	}()

	go func() {
		key := GenerateSecp256k1()
		config := NewConfig(key)
		addr := <-addrChan
		conn, _ := net.Dial("tcp", addr.String())
		sec, err := config.Handshake(conn)
		if err != nil {
			panic(err)
		}
		sec.Write(data)
		recv := make([]byte, 11)
		sec.Read(recv)
		dataChan <- recv
	}()

	re := <-dataChan

	if !bytes.Equal(data, re) {
		t.Fatal("handshake test fail")
	}
}
