package main

import (
	"fmt"
	"net"

	"github.com/BurntSushi/toml"
)

var defaultConfig = `
listen_url = "0.0.0.0:6666"
secret = "dd000102030405060708090a0b0c0d0e0f"
#secret = "00000000000000000000000000000000"
`

type Config struct {
	Listen_Url string
	Secret     string
}

func handleConnection(conn net.Conn, secret *Secret) {
	// var initialPacket [initialHeaderSize]byte
	// _, err := io.ReadFull(conn, initialPacket[:])
	// if err != nil {
	// 	conn.Close()
	// 	return
	// }
	// // dump header
	// println("header: " + hex.EncodeToString(initialPacket[:]))
	// c, err := obfuscatedCryptoFromHeader(initialPacket, secret)
	// if err != nil {
	// 	println(err.Error())
	// 	conn.Close()
	// 	return
	// }
	// if true {
	// 	buf := make([]byte, 4)
	// 	err = c.ReadExact(buf, conn)

	// 	if err != nil {
	// 		println(err.Error())
	// 		conn.Close()
	// 		return
	// 	}
	// 	fmt.Printf("first packet bytes: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3])
	// }
	obfuscatedRoutine, err := obfuscatedRouterFromStream(conn, secret)
	if err != nil {
		println(err.Error())
		return
	}
	obfuscatedRoutine.Wait()
}

func main() {
	c := &Config{}
	_, err := toml.Decode(defaultConfig, &c)
	if err != nil {
		panic(err)
	}
	fmt.Printf("listen: %s, secret: %s\n", c.Listen_Url, c.Secret)
	secret, err := NewSecretHex(c.Secret)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", c.Listen_Url)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleConnection(conn, secret)
	}
}
