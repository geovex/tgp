package network_exchange

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/maplist"
	"github.com/geovex/tgp/internal/tgcrypt_encryption"
	"golang.org/x/net/proxy"
)

var (
	mpmLock                  sync.Mutex
	mpm                      *MiddleProxyManager
	connectTimeout           = time.Second * 5
	proxyListUpdateTime      = time.Second * 3600
	this2mpConnectRetryDelay = time.Millisecond * 1000
)

// get or create MiddleProxyManager
func getMiddleProxyManager(cfg *config.Config) (*MiddleProxyManager, error) {
	mpmLock.Lock()
	defer mpmLock.Unlock()
	if mpm == nil {
		mpmNew, err := NewMiddleProxyManager(cfg)
		if err != nil {
			return nil, err
		}
		mpm = mpmNew
	}
	return mpm, nil
}

type MiddleProxyManager struct {
	cfg                      *config.Config
	mutex                    sync.Mutex
	proxyListUpdateTicker    *time.Ticker
	middleV4                 *maplist.MapList[int16, string]
	middleV6                 *maplist.MapList[int16, string]
	mpSecret                 []byte
	this2mpConnectRetryTimer *time.Ticker
}

func NewMiddleProxyManager(cfg *config.Config) (*MiddleProxyManager, error) {
	m := &MiddleProxyManager{
		cfg:                      cfg,
		this2mpConnectRetryTimer: time.NewTicker(this2mpConnectRetryDelay),
		proxyListUpdateTicker:    time.NewTicker(proxyListUpdateTime),
	}
	err := m.updateProxyList()
	if err != nil {
		return nil, err
	}
	go m.proxyListUpdateRoutine()
	return m, nil
}

func (m *MiddleProxyManager) updateProxyList() error {
	// ccreate dialer according to proxy settings
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
	// get ipv4 list
	response, err = httpClient.Get(tgcrypt_encryption.MiddleConfigIp4)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get ip4 proxy list: %w", err)
	}
	ip4List, err := parseList(response.Body)
	if err != nil {
		return fmt.Errorf("failed to parse ip4 proxy list: %w", err)
	}
	// get ipv6 list
	response, err = httpClient.Get(tgcrypt_encryption.MiddleConfigIp6)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get ip6 proxy list: %w", err)
	}
	ip6List, err := parseList(response.Body)
	if err != nil {
		return fmt.Errorf("failed to parse ip6 proxy list: %w", err)
	}
	m.mutex.Lock()
	m.mpSecret = secret
	m.middleV4 = ip4List
	m.middleV6 = ip6List
	m.mutex.Unlock()
	return nil
}

func (m *MiddleProxyManager) proxyListUpdateRoutine() {
	for {
		_, ok := <-m.proxyListUpdateTicker.C
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
		return nil, fmt.Errorf("failed to parse ip6 proxy list: %w", scanner.Err())
	}
	return list, nil
}

func (m *MiddleProxyManager) GetProxy(dc int16) (url4, url6 string, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	url4, _ = m.middleV4.GetRandom(dc)
	url6, _ = m.middleV6.GetRandom(dc)
	if url4 == "" && url6 == "" {
		return "", "", fmt.Errorf("middle proxy not found")
	}
	return url4, url6, nil
}

type MiddleProxyStream struct {
	initiated     bool
	closed        atomic.Bool
	thisProtocol  uint8
	seq           uint32
	encryptionCtx *tgcrypt_encryption.MiddleCtx
	// rpcType        []byte
	// rpcKeySelector []byte
	// rpcSchema      []byte
	//rpcTimeStamp //not really needed after login
	clientAddr           netip.AddrPort
	middleProxyNonce     tgcrypt_encryption.RpcNonce
	middleProxySock      dataStream
	middleProxyMsgStream *msgBlockStream
	connId               [8]byte
}

//lint:ignore U1000 reserved for future use
func (m *MiddleProxyManager) connectRetry(dc int16, client net.Conn, cliProtocol uint8, addTag []byte) (*MiddleProxyStream, error) {
	for {
		<-m.this2mpConnectRetryTimer.C
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
	if mps != nil {
		return nil, fmt.Errorf("failed to create middle proxy stream")
	}
	return mps, nil
}

// try to connect to ipv6 and (if this fails) to ipv4
// only direct connections supported by Telegram middle-proxies (encryption is
// based on IPs)
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

func NewMiddleProxyStream(mpStream dataStream, client, mp net.Conn, addTag []byte, clientProtocol uint8) *MiddleProxyStream {
	// all panics heare are in case of client or mp are not actually TCP or something crasy like this
	this2mpLocalAddr := mp.LocalAddr() // client address
	this2mpLocalTcpAddr, ok := this2mpLocalAddr.(*net.TCPAddr)
	if !ok {
		panic("middle proxy connection has no local address")
	}
	middleProxyAddr := mp.RemoteAddr() // outbound address
	middleProxyTcpAddr, ok := middleProxyAddr.(*net.TCPAddr)
	if !ok {
		panic("middle proxy connection has no remote address")
	}
	ctx := tgcrypt_encryption.NewMiddleCtx(this2mpLocalTcpAddr.AddrPort(), middleProxyTcpAddr.AddrPort(), addTag)
	seq := uint32(0)
	seq -= 2
	cli2thisAddr := client.RemoteAddr()
	cli2thisTcpAddr, ok := cli2thisAddr.(*net.TCPAddr)
	if !ok {
		panic("clientent connection has no local address")
	}
	return &MiddleProxyStream{
		initiated:       false,
		closed:          atomic.Bool{},
		thisProtocol:    clientProtocol,
		clientAddr:      cli2thisTcpAddr.AddrPort(),
		seq:             seq,
		encryptionCtx:   ctx,
		middleProxySock: mpStream,
	}
}

func (s *MiddleProxyStream) Initiate() (err error) {
	if s.initiated {
		return nil
	} else {
		return s.initiateReally()
	}
}

// login into middle proxy
func (m *MiddleProxyStream) initiateReally() (err error) {
	m.initiated = true
	fmt.Println("initiating")
	initialMsgData := make([]byte, 0, 32)
	initialMsgData = append(initialMsgData, tgcrypt_encryption.RpcNonceTag[:]...)
	secret := mpm.GetSecret()
	keySelector := secret[:4]
	initialMsgData = append(initialMsgData, keySelector...) // key selector
	initialMsgData = append(initialMsgData, tgcrypt_encryption.RpcCryptoAesTag[:]...)
	timestampCli := binary.LittleEndian.AppendUint32([]byte{}, uint32((time.Now().Unix())%0x100000000))
	initialMsgData = append(initialMsgData, timestampCli...) // crypto timestamp
	initialMsgData = append(initialMsgData, m.encryptionCtx.CliNonce[:]...)
	msg := &message{
		data:     initialMsgData,
		quickack: false,
		seq:      m.seq,
	}
	middleProxyRawStream := newRawStream(m.middleProxySock, tgcrypt_encryption.Full)
	middleProxyMsgStream := newMsgBlockStream(middleProxyRawStream, 32)
	err = middleProxyMsgStream.WriteMsg(msg)
	if err != nil {
		return fmt.Errorf("failed to send initial message: %w", err)
	}
	m.seq++
	msg, err = middleProxyMsgStream.ReadMsg()
	if err != nil {
		fmt.Printf("failed to read initial reply: %v\n", err)
		return fmt.Errorf("failed to read initial reply: %w", err)
	}
	if len(msg.data) != 32 {
		return fmt.Errorf("invalid initial reply length: %d", len(msg.data))
	}
	rpcType := msg.data[:4]
	rpcKeySelector := msg.data[4:8]
	rpcSchema := msg.data[8:12]
	//rpcTimeStamp := reply.data[12:16]
	copy(m.middleProxyNonce[:], msg.data[16:32])
	// TODO: check timestamp
	if !bytes.Equal(rpcType, tgcrypt_encryption.RpcNonceTag[:]) ||
		!bytes.Equal(rpcKeySelector, keySelector) ||
		!bytes.Equal(rpcSchema, tgcrypt_encryption.RpcCryptoAesTag[:]) {
		return fmt.Errorf("invalid initial reply")
	}
	m.encryptionCtx.SetObf(m.middleProxyNonce[:], timestampCli, secret)
	m.middleProxyMsgStream = newMsgBlockStream(newBlockStream(m.middleProxySock, m.encryptionCtx.Obf), 32) //m.ctx.Obf.BlockSize())
	handshakeMsg := make([]byte, 0, 32)
	handshakeMsg = append(handshakeMsg, tgcrypt_encryption.RpcHandShakeTag[:]...)
	handshakeMsg = append(handshakeMsg, 0, 0, 0, 0)                //rpc flags
	handshakeMsg = append(handshakeMsg, []byte("IPIPPRPDTIME")...) //SENDER_PID
	handshakeMsg = append(handshakeMsg, []byte("IPIPPRPDTIME")...) //PEER_PID
	//fmt.Println(hex.EncodeToString(handshakeMsg))
	msg = &message{
		data:     handshakeMsg,
		quickack: false,
		seq:      m.seq,
	}
	err = m.middleProxyMsgStream.WriteMsg(msg)
	if err != nil {
		return fmt.Errorf("failed to send encrypted handshake message: %w", err)
	}
	m.seq++
	msg, err = m.middleProxyMsgStream.ReadMsg()
	if err != nil {
		fmt.Printf("failed to read encrypted handshake reply: %v\n", err)
		return fmt.Errorf("failed to read encrypted reply: %w", err)
	}
	if len(msg.data) != 32 {
		return fmt.Errorf("invalid encrypted handshake reply length: %d", len(msg.data))
	}
	if !bytes.Equal(msg.data[:4], tgcrypt_encryption.RpcHandShakeTag[:]) ||
		!bytes.Equal(msg.data[20:32], []byte("IPIPPRPDTIME")) {
		return fmt.Errorf("bad encrypted rpc handshake answer")
	}
	// fill rest fields
	rand.Read(m.connId[:])
	return nil
}

func (m *MiddleProxyStream) ReadSrvMsg() (*message, error) {
	msg, err := m.middleProxyMsgStream.ReadMsg()
	if err != nil {
		// filter closed stream false positives
		if !m.closed.Load() {
			fmt.Printf("failed to read middleproxy message: %v\n", err)
		}
		return nil, fmt.Errorf("failed to read message: %w", err)
	}
	if len(msg.data) < 4 {
		return nil, fmt.Errorf("wrong middleproxy message received")
	} else if bytes.Equal(msg.data[:4], tgcrypt_encryption.RpcProxyAnsTag[:]) && len(msg.data) > 16 {
		newmsg := message{
			data:     msg.data[16:],
			quickack: false,
		}
		return &newmsg, nil
	} else if bytes.Equal(msg.data[:4], tgcrypt_encryption.RpcSimpleAckTag[:]) && len(msg.data) >= 16 {
		newmsg := message{
			data:     msg.data[12:16],
			quickack: true,
		}
		return &newmsg, nil
	} else if bytes.Equal(msg.data[:4], tgcrypt_encryption.RpcCloseExtTag[:]) {
		fmt.Printf("End of middleproxy stream")
		return nil, fmt.Errorf("end of middleproxy stream")
	} else if bytes.Equal(msg.data[:4], tgcrypt_encryption.RpcUnknown[:]) {
		newmsg := message{
			data: nil,
		}
		return &newmsg, nil
	} else {
		fmt.Printf("Middleproxy message not parsed\n")
		return nil, fmt.Errorf("middleproxy message not parsed")
	}
}

func (m *MiddleProxyStream) WriteSrvMsg(msg *message) error {
	var flags uint32
	flags = tgcrypt_encryption.FlagHasAdTag | tgcrypt_encryption.FlagMagic | tgcrypt_encryption.FlagExtNode2
	switch m.thisProtocol {
	case tgcrypt_encryption.Abridged:
		flags |= tgcrypt_encryption.FlagAbbridged
	case tgcrypt_encryption.Intermediate:
		flags |= tgcrypt_encryption.FlagIntermediate
	case tgcrypt_encryption.Padded:
		flags |= tgcrypt_encryption.FlagIntermediate | tgcrypt_encryption.FlagPad
	default:
		return fmt.Errorf("unknown client protocol: %d", m.thisProtocol)
	}
	if msg.quickack {
		flags |= tgcrypt_encryption.FlagQuickAck
	}
	if bytes.Equal(msg.data[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		flags |= tgcrypt_encryption.FlagNotEncrypted
	}
	fullmsg := make([]byte, 0, 48+len(msg.data))
	fullmsg = append(fullmsg, tgcrypt_encryption.RpcProxyReqTag[:]...)
	fullmsg = binary.LittleEndian.AppendUint32(fullmsg, flags)
	fullmsg = append(fullmsg, m.connId[:]...)
	// TODO: option for obfuscation
	ip6 := m.clientAddr.Addr().As16()
	if m.clientAddr.Addr().Is4() {
		ip6[10] = 0xff
		ip6[11] = 0xff
	}
	// ip6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	fullmsg = append(fullmsg, ip6[:]...)
	fullmsg = binary.LittleEndian.AppendUint32(fullmsg, uint32(m.encryptionCtx.MP.Port()))
	ip6Cli := m.encryptionCtx.Out.Addr().As16()
	if m.encryptionCtx.Out.Addr().Is4() {
		ip6Cli[10] = 0xff
		ip6Cli[11] = 0xff
	}
	//ip6Cli := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	fullmsg = append(fullmsg, ip6Cli[:]...)
	fullmsg = binary.LittleEndian.AppendUint32(fullmsg, uint32(m.encryptionCtx.Out.Port()))
	fullmsg = append(fullmsg, tgcrypt_encryption.ExtraSize[:]...)
	fullmsg = append(fullmsg, tgcrypt_encryption.ProxyTag[:]...)
	fullmsg = append(fullmsg, uint8(len(m.encryptionCtx.AdTag)))
	fullmsg = append(fullmsg, m.encryptionCtx.AdTag...)
	fullmsg = append(fullmsg, 0, 0, 0) //allign bytes
	data := msg.data[:len(msg.data)-len(msg.data)%4]
	fullmsg = append(fullmsg, data...) //trim padded message

	wrappedMsg := message{
		data:     fullmsg,
		quickack: false,
		seq:      m.seq,
	}
	err := m.middleProxyMsgStream.WriteMsg(&wrappedMsg)
	if err != nil {
		fmt.Printf("failed to send message: %v\n", err)
		return fmt.Errorf("failed to send message: %w", err)
	}
	m.seq++
	return nil
}

func (s *MiddleProxyStream) CloseStream() error {
	s.closed.Store(true)
	if s.middleProxyMsgStream == nil {
		return nil
	} else {
		return s.middleProxyMsgStream.CloseStream()
	}
}
