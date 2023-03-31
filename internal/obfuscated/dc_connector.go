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

// Connects client to the specified DC or fallback host
type DCConnector interface {
	// Connect to the specified DC by it's number (may be negative)
	ConnectDC(dc int16) (c net.Conn, err error)
	// Connects to specific host (for fallback connections)
	ConnectHost(host string) (c net.Conn, err error)
}

// Directly connects client
type DcDirectConnector struct {
	allowIPv6 bool
}

// creates a new DcDirectConnector
func NewDcDirectConnector(allowIPv6 bool) *DcDirectConnector {
	return &DcDirectConnector{
		allowIPv6: allowIPv6,
	}
}

// Connects client to the specified DC directly
func (dcc *DcDirectConnector) ConnectDC(dc int16) (c net.Conn, err error) {
	dcAddr4, dcAddr6, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	c, err4, err6 := dialBoth(dcAddr4, dcAddr6, proxy.Direct)
	if err4 != nil || err6 != nil {
		return nil, fmt.Errorf("can't connect to dc %w, %w", err4, err6)
	}
	setNoDelay(c)
	return c, err
}

func (dcc *DcDirectConnector) ConnectHost(host string) (net.Conn, error) {
	c, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	setNoDelay(c)
	return c, nil
}

// Connects client over SOCKS5 proxy
type DcSocksConnector struct {
	allowIPv6 bool
	user      *string
	pass      *string
	socks5    string
}

// Create a new DcSocksConnector
func NewDcSocksConnector(allowIPv6 bool, socks5 string, user, pass *string) *DcSocksConnector {
	return &DcSocksConnector{
		allowIPv6: allowIPv6,
		user:      user,
		pass:      pass,
		socks5:    socks5,
	}
}

// create proxy dialer according to socks5 url and auth
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
		return nil, fmt.Errorf("proxy dialer not created: %w", err)
	}
	return dialer, nil
}

// connect to the specified DC over socks5
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
		return nil, fmt.Errorf("can't connect to dc: %w, %w", err4, err6)
	}
	setNoDelay(c)
	return
}

func (dsc *DcSocksConnector) ConnectHost(host string) (net.Conn, error) {
	dialer, err := dsc.createDialer()
	if err != nil {
		return nil, err
	}
	c, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("can't connect to host %w", err)
	}
	setNoDelay(c)
	return c, nil
}

// Try to dial both ipv4 and ipv6 addresses and return resulting connection
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

// if socks5 info is specified, return socks5 DcSocksConnector else return direct DcDirectConnector
func dcConnectorFromSocks(s *config.Socks5Data, allowIPv6 bool) (conn DCConnector, err error) {
	if s == nil {
		return NewDcDirectConnector(allowIPv6), nil
	} else {
		return NewDcSocksConnector(allowIPv6, s.Url, s.User, s.Pass), nil
	}
}

// Set nodelay to supposedly socket object. Do nothing otherwise.
func setNoDelay(c net.Conn) {
	sock, ok := c.(*net.TCPConn)
	if ok {
		sock.SetNoDelay(true)
	}
}
