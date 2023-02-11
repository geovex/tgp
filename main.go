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
