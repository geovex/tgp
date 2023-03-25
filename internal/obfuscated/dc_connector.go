package obfuscated

import (
	"fmt"
	"math/rand"
	"net"

	"golang.org/x/net/proxy"
)

const dc_port = "443"

var dc_ip4 = [...][]string{
	{"149.154.175.50"},
	{"149.154.167.51", "95.161.76.100"},
	{"149.154.175.100"},
	{"149.154.167.91"},
	{"149.154.171.5"},
}

// var dc_ip6 = [...]string{
// 	{"2001:b28:f23d:f001::a"},
// 	{"2001:67c:04e8:f002::a"},
// 	{"2001:b28:f23d:f003::a"},
// 	{"2001:67c:04e8:f004::a"},
// 	{"2001:b28:f23f:f005::a"},
// }

func getDcAddr(dc int16) (string, error) {
	if dc < 0 {
		dc = -dc
	}
	if dc < 1 || dc > int16(len(dc_ip4)) {
		return "", fmt.Errorf("invalid dc number %d", dc)
	}
	dcIdxList := dc_ip4[dc-1]
	dcSubidx := rand.Intn(len(dcIdxList))
	dcAddr := dc_ip4[dc-1][dcSubidx] + ":" + dc_port
	return dcAddr, nil
}

type DCConnector interface {
	ConnectDC(dc int16) (c net.Conn, err error)
}

type DcDirectConnector struct{}

func NewDcDirectConnector() *DcDirectConnector {
	return &DcDirectConnector{}
}

func (dcc *DcDirectConnector) ConnectDC(dc int16) (c net.Conn, err error) {
	dcAddr, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	c, err = net.Dial("tcp", dcAddr)
	sock, ok := c.(*net.TCPConn)
	if ok {
		//fmt.Fprintf("nodelay: %s\n", sock.)
		sock.SetNoDelay(true)

	}
	return c, err
}

type DcSocksConnector struct {
	socks5 string
}

func NewDcSocksConnector(socks5 string) *DcSocksConnector {
	return &DcSocksConnector{socks5}
}

func (dsc *DcSocksConnector) ConnectDC(dc int16) (c net.Conn, err error) {
	dialer, err := proxy.SOCKS5("tcp", dsc.socks5, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	dcAddr, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	c, err = dialer.Dial("tcp", dcAddr)
	if err != nil {
		return nil, err
	}
	sock, ok := c.(*net.TCPConn)
	if ok {
		//fmt.Fprintf("nodelay: %s\n", sock.)
		sock.SetNoDelay(true)

	}
	return
}
