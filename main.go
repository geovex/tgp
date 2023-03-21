package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

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
	handleObfuscated(conn, dcConn, userDB)
}

func listenForConnections(listener net.Listener, dcc DCConnector, userDB *Users) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn, dcc, userDB)
	}
}

func main() {
	var configData []byte
	if len(os.Args) > 1 {
		var err error
		configData, err = ioutil.ReadFile(os.Args[1])
		if err != nil {
			panic(err)
		}
	} else {
		configData = []byte(defaultConfig)
	}
	c := &Config{}
	_, err := toml.Decode(string(configData), &c)
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
	defer listener.Close()
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
	_ = listenForConnections(listener, dcc, userDB)
}
