package main

import (
	"fmt"
	"net"
	"os"

	"github.com/geovex/tgp/internal/config"
	o "github.com/geovex/tgp/internal/obfuscated"
)

func handleConnection(conn net.Conn, dcConn o.DCConnector, userDB *config.Users) {
	o.HandleObfuscated(conn, dcConn, userDB)
}

func listenForConnections(listener net.Listener, dcc o.DCConnector, userDB *config.Users) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn, dcc, userDB)
	}
}

func main() {
	var c *config.Config
	if len(os.Args) > 1 {
		var err error
		c, err = config.ReadConfig(os.Args[1])
		if err != nil {
			panic(err)
		}
	} else {
		c = config.DefaultConfig()
	}
	fmt.Printf("listen: %s\n", c.Listen_Url)
	listener, err := net.Listen("tcp", c.Listen_Url)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	var userDB *config.Users
	if c.Users != nil && c.Secret == nil {
		userDB = config.NewUsersMap(*c.Users)
	} else if c.Users == nil && c.Secret != nil {
		userDB = config.NewUsersSecret(*c.Secret)
	} else {
		panic("specify either secret or users")
	}
	var dcc o.DCConnector
	if c.Socks5 != nil {
		dcc = o.NewDcSocksConnector(*c.Socks5)
	} else {
		dcc = o.NewDcDirectConnector()
	}
	_ = listenForConnections(listener, dcc, userDB)
}

func DefaultConfig() {
	panic("unimplemented")
}
