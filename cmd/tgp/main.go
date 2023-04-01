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

func (cl *connectionListener) handleLListener(url string) error {
	fmt.Printf("listen: %s\n", url)
	l, err := net.Listen("tcp", url)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		sock, ok := conn.(*net.TCPConn)
		if ok {
			sock.SetNoDelay(true)
		}
		oh := o.NewObfuscatedHandler(cl.conf, conn)
		go oh.HandleObfuscated()
	}
}

func (cl *connectionListener) listenForConnections() error {
	waiter := make(chan error, 1)
	defer close(waiter)
	for _, url := range cl.conf.GetListenUrl() {
		waiter := make(chan error, 1)
		go func(u string) { waiter <- cl.handleLListener(u) }(url)
	}
	err := <-waiter
	return err
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
	cl := newConnectionListener(c)
	err := cl.listenForConnections()
	if err != nil {
		panic(err)
	}
}

func DefaultConfig() {
	panic("unimplemented")
}
