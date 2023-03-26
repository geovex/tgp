package main

import (
	"fmt"
	"net"
	"os"

	"github.com/geovex/tgp/internal/config"
	o "github.com/geovex/tgp/internal/obfuscated"
)

func handleConnection(conn net.Conn, userDB *config.Users) {
	o.HandleObfuscated(conn, userDB)
}

func listenForConnections(listener net.Listener, userDB *config.Users) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		sock, ok := conn.(*net.TCPConn)
		if ok {
			sock.SetNoDelay(true)
		}
		go handleConnection(conn, userDB)
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
	_ = listenForConnections(listener, c.Users)
}

func DefaultConfig() {
	panic("unimplemented")
}
