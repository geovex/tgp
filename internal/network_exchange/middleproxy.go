package network_exchange

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/maplist"
	"github.com/geovex/tgp/internal/tgcrypt_encryption"
	"golang.org/x/net/proxy"
)

var (
	mpmLock sync.Mutex
	mpm     *MiddleProxyManager
)

const (
	connectTimeout           = time.Second * 5
	proxyListUpdateTime      = time.Second * 3600
	this2mpConnectRetryDelay = time.Millisecond * 1000
)

// get or create MiddleProxyManager simpliest of configs does not require all
// this. So we try lazy-init all this subsystem only in case it's needed.
func getMiddleProxyManager(cfg *config.Config) (*MiddleProxyManager, error) {
	mpmLock.Lock()
	defer mpmLock.Unlock()
	if mpm == nil {
		mpmNew, err := NewMiddleProxyManager(cfg)
		if err != nil {
			return nil, fmt.Errorf("can't create middle proxy manager: %w", err)
		}
		mpm = mpmNew
	}
	return mpm, nil
}

type MiddleProxyManager struct {
	cfg      *config.Config
	mutex    sync.Mutex
	middleV4 *maplist.MapList[int16, string]
	middleV6 *maplist.MapList[int16, string]
	mpSecret []byte
}

func NewMiddleProxyManager(cfg *config.Config) (*MiddleProxyManager, error) {
	m := &MiddleProxyManager{
		cfg: cfg,
	}
	err := m.updateProxyList()
	if err != nil {
		return nil, fmt.Errorf("failed to update proxy list: %w", err)
	}
	go m.proxyListUpdateRoutine()
	return m, nil
}

// updates proxy list from official site
// TODO default managers for different clients
func (m *MiddleProxyManager) updateProxyList() error {
	// create dialer according to proxy settings
	var dialer proxy.Dialer
	sa, su, sp := m.cfg.GetDefaultSocks()
	if sa == nil {
		dialer = proxy.Direct
	} else {
		var auth *proxy.Auth
		if su != nil {
			auth = &proxy.Auth{
				User:     *su,
				Password: *sp,
			}
		}
		var err error
		dialer, err = proxy.SOCKS5("tcp", *sa, auth, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to create socks5 proxy dialer: %w", err)
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}
	// TODO: this can be in parallel
	response, err := httpClient.Get(tgcrypt_encryption.MiddleSecretUrl)
	if err != nil {
		return fmt.Errorf("failed to get proxy secret: %w", err)
	}
	// get secret
	secret, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read proxy secret: %w", err)
	}
	getList := func(url, ip_type string) (*maplist.MapList[int16, string], error) {
		response, err := httpClient.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to get ipv%s proxy list: %w", ip_type, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get ipv%s proxy list (status code: %d)", ip_type, response.StatusCode)
		}
		ipList, err := parseList(response.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ipv%s proxy list: %w", ip_type, err)
		}
		return ipList, nil
	}
	// get ipv4 list
	ip4List, err := getList(tgcrypt_encryption.MiddleConfigIp4, "4")
	if err != nil {
		return err
	}
	// get ipv6 list
	ip6List, err := getList(tgcrypt_encryption.MiddleConfigIp6, "6")
	if err != nil {
		return err
	}
	m.mutex.Lock()
	m.mpSecret = secret
	m.middleV4 = ip4List
	m.middleV6 = ip6List
	m.mutex.Unlock()
	return nil
}

func (m *MiddleProxyManager) proxyListUpdateRoutine() {
	updateTimer := time.NewTicker(proxyListUpdateTime)
	defer updateTimer.Stop()
	for {
		_, ok := <-updateTimer.C
		if ok {
			err := m.updateProxyList()
			if err != nil {
				fmt.Printf("failed to update middleproxy list: %v\n", err)
			}
		} else {
			return
		}
	}
}

// get secret for middle proxies
func (m *MiddleProxyManager) GetSecret() []byte {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return append([]byte{}, m.mpSecret...)
}

func parseList(r io.ReadCloser) (*maplist.MapList[int16, string], error) {
	scanner := bufio.NewScanner(r)
	list := maplist.New[int16, string]()
	for scanner.Scan() {
		text := scanner.Text()
		var id int16
		var url string
		_, err := fmt.Sscanf(text, "proxy_for %d %s", &id, &url)
		if len(url) > 1 {
			url = url[:len(url)-1]
		}
		if err != nil {
			continue
		}
		list.Add(id, url)
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("failed to parse proxy list: %w", scanner.Err())
	}
	return list, nil
}

func (m *MiddleProxyManager) GetProxy(dc int16) (url4, url6 string, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	url4, _ = m.middleV4.GetRandom(dc)
	url6, _ = m.middleV6.GetRandom(dc)
	if url4 == "" && url6 == "" {
		return "", "", fmt.Errorf("middle proxy not found for dc: %d", dc)
	}
	return url4, url6, nil
}

//lint:ignore U1000 reserved for future use
func (m *MiddleProxyManager) connectRetry(dc int16, client net.Conn, cliProtocol uint8, addTag []byte) (*MiddleProxyStream, error) {
	reconnectTimer := time.NewTicker(this2mpConnectRetryDelay)
	defer reconnectTimer.Stop()
	for {
		<-reconnectTimer.C
		mp, err := m.connect(dc, client, cliProtocol, addTag)
		if err != nil {
			continue
		}
		err = mp.Initiate()
		if err != nil {
			continue
		}
		return mp, nil
	}
}

func (m *MiddleProxyManager) connect(dc int16, client net.Conn, clientProtocol uint8, addTag []byte) (*MiddleProxyStream, error) {
	//fmt.Printf("middle connect dc: %d\n", dc)
	url4, url6, err := m.GetProxy(dc)
	if err != nil {
		return nil, err
	}
	if !m.cfg.GetAllowIPv6() {
		url6 = ""
	}
	fmt.Printf("connecting to %d, %s %s\n", dc, url4, url6)
	this2middle, err := connect64(url4, url6)
	if err != nil {
		fmt.Printf("middleproxy connection failed\n")
		return nil, err
	}
	this2middleTcp, ok := this2middle.(*net.TCPConn)
	if !ok {
		panic("failed to cast tcp connection")
	}
	this2middleTcp.SetNoDelay(true)
	rs := newRawStream(this2middle, tgcrypt_encryption.Full)
	mps := NewMiddleProxyStream(rs, client, this2middle, addTag, clientProtocol)
	if mps == nil {
		panic(fmt.Errorf("failed to create middle proxy stream"))
	}
	return mps, nil
}

// try to connect to ipv6 and (if this fails) to ipv4
// only direct connections supported by Telegram middle-proxies (encryption is
// based on IPs)
// TODO: wrap error into struct
func connect64(url4, url6 string) (c net.Conn, err error) {
	var err6, err4 error
	if url6 != "" {
		c, err6 = net.DialTimeout("tcp", url6, connectTimeout)
		if err6 == nil {
			return c, nil
		}
	}
	c, err4 = net.DialTimeout("tcp", url4, connectTimeout)
	if err4 == nil {
		return c, nil
	}
	tcp, ok := c.(*net.TCPConn)
	if ok {
		tcp.SetNoDelay(false)
	}
	return nil, fmt.Errorf("can't connect to middle proxy %w %w", err4, err6)
}
