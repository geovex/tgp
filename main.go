package main

import (
	"fmt"
	"net"
	"os"
)

func handleConnection(conn net.Conn, dcConn DCConnector, userDB *Users) {
	handleSimple(conn, dcConn, userDB)
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
	var c *Config
	if len(os.Args) > 1 {
		var err error
		c, err = readConfig(os.Args[1])
		if err != nil {
			panic(err)
		}
	} else {
		c = defaultConfig()
	}
	fmt.Printf("listen: %s\n", c.Listen_Url)
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
