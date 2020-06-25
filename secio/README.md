## tentacle-secio-go

This is the Go implementation of the secio layer in the tentacle framework. Currently, it can already shake hands and communicate normally. The protocol can be seen in the [Rust](https://github.com/nervosnetwork/tentacle) version.


### Usage

client: 

```go
func main() {
    key := secio.GenerateSecp256k1()
    config := secio.NewConfig(key)

    // Get a TCP connection
    conn, _ := net.Dial("tcp", ":1337")

    sec, _ := config.Handshake(conn)
    sec.Write([]byte("hello world"))
    recv := make([]byte, 11)
    sec.Read(recv)
}
```

server:

```go
func main() {
    key := GenerateSecp256k1()
    config := NewConfig(key)

    listener, _ := net.Listen("tcp", ":0")
    defer listener.Close()

    for {
        conn, _ := listener.Accept()
        go func() {
            sec, _ := config.Handshake(conn)
            recv := make([]byte, 11)
            sec.Read(recv)
            sec.Write(recv)
        }()
    }
}
```

### Thanks

Most of this project is a translation of the implementation of the Rust version, and a small part borrows from the [go-libp2p-secio](https://github.com/libp2p/go-libp2p-secio) project
