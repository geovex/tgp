package main

import (
	"fmt"
	"net"
	"os"

	"github.com/geovex/tgp/internal/config"
	o "github.com/geovex/tgp/internal/obfuscated"
	"github.com/geovex/tgp/internal/stats"
)

type server struct {
	stats *stats.Stats
	conf  *config.Config
}

func newServer(conf *config.Config) *server {
	return &server{
		stats: stats.New(),
		conf:  conf,
	}
}

func (s *server) handleListener(url string) error {
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
		oh := o.NewClient(s.conf, s.stats.AllocClient(), conn)
		go oh.HandleClient()
		//oh.HandleClient()
	}
}

func (s *server) run() error {
	proxy := make(chan error, 1)
	defer close(proxy)
	for _, url := range s.conf.GetListenUrl() {
		waiter := make(chan error, 1)
		go func(u string) { waiter <- s.handleListener(u) }(url)
	}
	stats := make(chan error, 1)
	defer close(stats)
	go func() { stats <- s.listenForStats() }()
	errProxy := <-proxy
	errStats := <-stats
	if errProxy != nil || errStats != nil {
		return fmt.Errorf("server stopped with errors: proxy: %v, stats: %v", errProxy, errStats)
	} else {
		return nil
	}
}

func (s *server) listenForStats() error {
	sockPath := s.conf.GetStatsSock()
	if sockPath == nil || *sockPath == "" {
		//no stats socket specified
		return nil
	}
	l, err := net.Listen("unix", *sockPath)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		statsString := s.stats.AsString()
		conn.Write([]byte(statsString))
		conn.Close()
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
	cl := newServer(c)
	cl.run()
	// err := cl.run()
	// if err != nil {
	// 	panic(err)
	// }
}
