package main

import (
	"fmt"
	"net"

	"github.com/BurntSushi/toml"
)

var defaultConfig = `
listen_url = "0.0.0.0:6666"
#secret = "dd000102030405060708090a0b0c0d0e0f"
socks5 = "127.0.0.1:9050"
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
2 = "dd101112131415161718191a1b1c1d1e1f"
`

type Config struct {
	Listen_Url string
	Secret     *string
	Socks5     *string
	Users      *map[string]string
}

func handleConnection(conn net.Conn, dcConn DCConnector, userDB *Users) {
	obfuscatedRoutine, err := obfuscatedRouterFromStream(conn, dcConn, userDB)
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
	fmt.Printf("listen: %s\n", c.Listen_Url)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", c.Listen_Url)
	if err != nil {
		panic(err)
	}
	var userDB *Users
	if c.Users != nil && c.Secret == nil {
		userDB = NewUsersMap(*c.Users)
	} else if c.Users == nil && c.Secret != nil {
		userDB = NewUsersSecret(*c.Secret)
	} else {
		panic("specify either secret or users")
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
		go handleConnection(conn, dcc, userDB)
	}
}
