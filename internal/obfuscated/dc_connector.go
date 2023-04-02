package obfuscated

import (
	"fmt"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/maplist"
	"golang.org/x/net/proxy"
)

const dcMaxIdx = int16(5)

var dc_ip4 = maplist.MapList[int16, string]{
	Data: map[int16][]string{
		1: {"149.154.175.50:443"},
		2: {"149.154.167.51:443", "95.161.76.100:443"},
		3: {"149.154.175.100:443"},
		4: {"149.154.167.91:443"},
		5: {"149.154.171.5:443"},
	},
}

var dc_ip6 = maplist.MapList[int16, string]{
	Data: map[int16][]string{
		1: {"[2001:b28:f23d:f001::a]:443"},
		2: {"[2001:67c:04e8:f002::a]:443"},
		3: {"[2001:b28:f23d:f003::a]:443"},
		4: {"[2001:67c:04e8:f004::a]:443"},
		5: {"[2001:b28:f23f:f005::a]:443"},
	},
}

func getDcAddr(dc int16) (ipv4, ipv6 string, err error) {
	if dc < 0 {
		dc = -dc
	}
	if dc < 1 || dc > dcMaxIdx {
		return "", "", fmt.Errorf("invalid dc number %d", dc)
	}
	ipv4, _ = dc_ip4.GetRandom(dc)
	ipv6, _ = dc_ip6.GetRandom(dc)
	if ipv4 == "" && ipv6 == "" {
		return "", "", fmt.Errorf("invalid dc number %d", dc)
	}
	return ipv4, ipv6, nil
}

// Connects client to the specified DC or fallback host
type DCConnector interface {
	// Connect to the specified DC by it's number (may be negative)
	ConnectDC(dc int16) (c io.ReadWriteCloser, err error)
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
func (dcc *DcDirectConnector) ConnectDC(dc int16) (stream io.ReadWriteCloser, err error) {
	dcAddr4, dcAddr6, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	if !dcc.allowIPv6 {
		dcAddr6 = ""
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
func (dsc *DcSocksConnector) ConnectDC(dc int16) (io.ReadWriteCloser, error) {
	dialer, err := dsc.createDialer()
	if err != nil {
		return nil, err
	}
	dcAddr4, dcAddr6, err := getDcAddr(dc)
	if err != nil {
		return nil, err
	}
	if !dsc.allowIPv6 {
		dcAddr6 = ""
	}
	c, err4, err6 := dialBoth(dcAddr4, dcAddr6, dialer)
	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("can't connect to dc: %w, %w", err4, err6)
	}
	setNoDelay(c)
	return c, nil
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
