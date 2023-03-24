package obfuscated

import (
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

const dc_port = "443"

var dc_ip4 = [...]string{
	"149.154.175.50",
	"149.154.167.51",
	"149.154.175.100",
	"149.154.167.91",
	"149.154.171.5",
}

// var dc_ip6 = [...]string{
// 	"2001:b28:f23d:f001::a",
// 	"2001:67c:04e8:f002::a",
// 	"2001:b28:f23d:f003::a",
// 	"2001:67c:04e8:f004::a",
// 	"2001:b28:f23f:f005::a",
// }

func normalizeDcNum(dc int16) (int16, error) {
	if dc < 0 {
		dc = -dc
	}
	if dc < 1 || dc > int16(len(dc_ip4)) {
		return 0, fmt.Errorf("invalid dc number %d", dc)
	}
	return dc, nil
}

type DCConnector interface {
	ConnectDC(dc int16) (c net.Conn, err error)
}

type DcDirectConnector struct{}

func NewDcDirectConnector() *DcDirectConnector {
	return &DcDirectConnector{}
}

func (dcc *DcDirectConnector) ConnectDC(dc int16) (c net.Conn, err error) {
	dc, err = normalizeDcNum(dc)
	if err != nil {
		return nil, err
	}
	dc_addr := dc_ip4[dc-1] + ":" + dc_port
	c, err = net.Dial("tcp", dc_addr)
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
	dc, err = normalizeDcNum(dc)
	if err != nil {
		return nil, err
	}
	dc_addr := dc_ip4[dc-1] + ":" + dc_port
	c, err = dialer.Dial("tcp", dc_addr)
	if err != nil {
		return nil, err
	}
	return
}
