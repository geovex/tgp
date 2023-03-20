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
socks5 = "127.0.0.1:9050"
`

type Config struct {
	Listen_Url string
	Secret     string
	Socks5     *string
}

func handleConnection(conn net.Conn, secret *Secret, dcConn DCConnector) {
	obfuscatedRoutine, err := obfuscatedRouterFromStream(conn, secret, dcConn)
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
	var dcc DCConnector
	if c.Socks5 != nil {
		dcc = NewDcSocksConnector(*c.Socks5)
	} else {
		dcc = NewDcDirectConnector()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleConnection(conn, secret, dcc)
	}
}
