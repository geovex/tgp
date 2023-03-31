package obfuscated

import (
	"fmt"
	"math/rand"
	"net"

	"github.com/geovex/tgp/internal/config"
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

var dc_ip6 = [...][]string{
	{"[2001:b28:f23d:f001::a]"},
	{"[2001:67c:04e8:f002::a]"},
	{"[2001:b28:f23d:f003::a]"},
	{"[2001:67c:04e8:f004::a]"},
	{"[2001:b28:f23f:f005::a]"},
}

func getDcAddr(dc int16) (ipv4, ipv6 string, err error) {
	if dc < 0 {
		dc = -dc
	}
	if dc < 1 || dc > int16(len(dc_ip4)) {
		return "", "", fmt.Errorf("invalid dc number %d", dc)
	}
	dcIdxList := dc_ip4[dc-1]
	dcSubidx := rand.Intn(len(dcIdxList))
	dcAddr4 := dc_ip4[dc-1][dcSubidx] + ":" + dc_port
	dcIdxList = dc_ip6[dc-1]
	dcSubidx = rand.Intn(len(dcIdxList))
	dcAddr6 := dc_ip6[dc-1][dcSubidx] + ":" + dc_port
	return dcAddr4, dcAddr6, nil
}

type DCConnector interface {
	ConnectDC(dc int16) (c net.Conn, err error)
	ConnectHost(host string) (c net.Conn, err error)
}

type DcDirectConnector struct {
	allowIPv6 bool
}

func NewDcDirectConnector(allowIPv6 bool) *DcDirectConnector {
	return &DcDirectConnector{
		allowIPv6: allowIPv6,
	}
}

func (dcc *DcDirectConnector) ConnectDC(dc int16) (c net.Conn, err error) {
	dcAddr4, dcAddr6, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	c, err4, err6 := dialBoth(dcAddr4, dcAddr6, proxy.Direct)
	if err4 != nil || err6 != nil {
		return nil, fmt.Errorf("can't connect to dc %v, %v", err4, err6)
	}
	sock, ok := c.(*net.TCPConn)
	if ok {
		//fmt.Fprintf("nodelay: %s\n", sock.)
		sock.SetNoDelay(true)

	}
	return c, err
}

func (dcc *DcDirectConnector) ConnectHost(host string) (net.Conn, error) {
	c, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	sock, ok := c.(*net.TCPConn)
	if ok {
		sock.SetNoDelay(true)
	}
	return c, nil
}

type DcSocksConnector struct {
	allowIPv6 bool
	user      *string
	pass      *string
	socks5    string
}

func NewDcSocksConnector(allowIPv6 bool, socks5 string, user, pass *string) *DcSocksConnector {
	return &DcSocksConnector{
		allowIPv6: allowIPv6,
		user:      user,
		pass:      pass,
		socks5:    socks5,
	}
}

func (dsc *DcSocksConnector) createDialer() (proxy.Dialer, error) {
	var auth *proxy.Auth
	if dsc.user != nil && dsc.pass != nil {
		auth = &proxy.Auth{
			User:     *dsc.user,
			Password: *dsc.pass,
		}
	}
	dialer, err := proxy.SOCKS5("tcp", dsc.socks5, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer, nil
}

func (dsc *DcSocksConnector) ConnectDC(dc int16) (c net.Conn, err error) {
	dialer, err := dsc.createDialer()
	if err != nil {
		return nil, err
	}
	dcAddr4, dcAddr6, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	c, err4, err6 := dialBoth(dcAddr4, dcAddr6, dialer)
	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("can't connect to dc: %v, %v", err4, err6)
	}
	sock, ok := c.(*net.TCPConn)
	if ok {
		sock.SetNoDelay(true)
	}
	return
}

func (dsc *DcSocksConnector) ConnectHost(host string) (net.Conn, error) {
	dialer, err := dsc.createDialer()
	if err != nil {
		return nil, err
	}
	c, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	sock, ok := c.(*net.TCPConn)
	if ok {
		sock.SetNoDelay(true)
	}
	return c, nil
}

func dialBoth(host4, host6 string, dialer proxy.Dialer) (c net.Conn, err4, err6 error) {
	if host6 != "" {
		c, err6 = dialer.Dial("tcp", host6)
		if err6 == nil {
			return
		}
	}
	c, err4 = dialer.Dial("tcp", host4)
	if err4 != nil {
		return nil, err4, err6
	}
	return
}

func dcConnectorFromSocks(s *config.Socks5Data, allowIPv6 bool) (conn DCConnector, err error) {
	if s == nil {
		return NewDcDirectConnector(allowIPv6), nil
	} else {
		return NewDcSocksConnector(allowIPv6, s.Url, s.User, s.Pass), nil
	}
}
