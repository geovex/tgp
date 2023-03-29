package main

import (
	"fmt"
	"net"
	"os"

	"github.com/geovex/tgp/internal/config"
	o "github.com/geovex/tgp/internal/obfuscated"
)

type connectionListener struct {
	conf *config.Config
}

func newConnectionListener(conf *config.Config) *connectionListener {
	return &connectionListener{
		conf: conf,
	}
}

func (cl *connectionListener) listenForConnections() error {
	listener, err := net.Listen("tcp", cl.conf.GetListenUrl())
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		sock, ok := conn.(*net.TCPConn)
		if ok {
			sock.SetNoDelay(true)
		}
		oh := o.NewObfuscatedHandler(cl.conf)
		go oh.HandleObfuscated(conn)
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
	cl := newConnectionListener(c)
	err := cl.listenForConnections()
	if err != nil {
		panic(err)
	}
}

func DefaultConfig() {
	panic("unimplemented")
}
