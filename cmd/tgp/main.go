package main

import (
	"fmt"
	"net"
	"os"

	"github.com/geovex/tgp/internal/config"
	o "github.com/geovex/tgp/internal/obfuscated"
)

func handleConnection(conn net.Conn, conf *config.Config) {
	o.HandleObfuscated(conn, conf)
}

func listenForConnections(listener net.Listener, conf *config.Config) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		sock, ok := conn.(*net.TCPConn)
		if ok {
			sock.SetNoDelay(true)
		}
		go handleConnection(conn, conf)
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
	fmt.Printf("listen: %s\n", c.GetListenUrl())
	listener, err := net.Listen("tcp", c.GetListenUrl())
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	_ = listenForConnections(listener, c)
}

func DefaultConfig() {
	panic("unimplemented")
}
