package obfuscated

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
	"time"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/maplist"
	"github.com/geovex/tgp/internal/tgcrypt"
	"golang.org/x/net/proxy"
)

const middleSecretUrl = "https://core.telegram.org/getProxySecret"
const middleConfigIp4 = "https://core.telegram.org/getProxyConfig"
const middleConfigIp6 = "https://core.telegram.org/getProxyConfigV6"

const updateTime = 3600

var mpmLock sync.Mutex
var mpm *MiddleProxyManager

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
	cfg      *config.Config
	mutex    sync.Mutex
	middleV4 *maplist.MapList[int16, string]
	middleV6 *maplist.MapList[int16, string]
	secret   []byte
	timer    *time.Ticker
}

func NewMiddleProxyManager(cfg *config.Config) (*MiddleProxyManager, error) {
	m := &MiddleProxyManager{
		cfg:   cfg,
		timer: time.NewTicker(time.Millisecond * 1000),
	}
	err := m.updateData()
	if err != nil {
		return nil, err
	}
	go m.updateRoutine()
	return m, nil
}

func (m *MiddleProxyManager) updateData() error {
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
	response, err := httpClient.Get(middleSecretUrl)
	if err != nil {
		return fmt.Errorf("failed to get proxy secret: %w", err)
	}
	// get secret
	secret, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read proxy secret: %w", err)
	}
	m.mutex.Lock()
	m.secret = secret
	m.mutex.Unlock()
	// get ipv4 list
	response, err = httpClient.Get(middleConfigIp4)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get ip4 proxy list: %w", err)
	}
	ip4List, err := parseList(response.Body)
	if err != nil {
		return fmt.Errorf("failed to parse ip4 proxy list: %w", err)
	}
	m.mutex.Lock()
	m.middleV4 = ip4List
	m.mutex.Unlock()
	// get ipv6 list
	response, err = httpClient.Get(middleConfigIp6)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get ip6 proxy list: %w", err)
	}
	ip6List, err := parseList(response.Body)
	if err != nil {
		return fmt.Errorf("failed to parse ip6 proxy list: %w", err)
	}
	m.mutex.Lock()
	m.middleV6 = ip6List
	m.mutex.Unlock()
	return nil
}

func (m *MiddleProxyManager) updateRoutine() {
	for {
		time.Sleep(time.Second * updateTime)
		m.updateData()
		// TODO process errors
		// TODO condition to stop (may be use ticker)
	}
}

// get secret for middle proxies
func (m *MiddleProxyManager) GetSecret() []byte {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return append([]byte{}, m.secret...)
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
	initiated bool
	protoCli  uint8
	seq       uint32
	ctx       *tgcrypt.MiddleCtx
	// rpcType        []byte
	// rpcKeySelector []byte
	// rpcSchema      []byte
	//rpcTimeStamp //not really needed after login
	cliAddr     netip.AddrPort
	mpNonce     tgcrypt.RpcNonce
	mSock       dataStream
	mDataStream *msgBlockStream
	connId      [8]byte
}

//lint:ignore U1000 reserved for future use
func (m *MiddleProxyManager) connectRetry(dc int16, client net.Conn, cliProtocol uint8, addTag []byte) (*MiddleProxyStream, error) {
	for {
		<-m.timer.C
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

func (m *MiddleProxyManager) connect(dc int16, client net.Conn, cliProtocol uint8, addTag []byte) (*MiddleProxyStream, error) {
	//fmt.Printf("middle connect dc: %d\n", dc)
	url4, url6, err := m.GetProxy(dc)
	if err != nil {
		return nil, err
	}
	if !m.cfg.GetAllowIPv6() {
		url6 = ""
	}
	fmt.Printf("connecting to %d, %s %s\n", dc, url4, url6)
	mp, err := connectBoth(url4, url6)
	if err != nil {
		fmt.Printf("middleproxy connection failed\n")
		if err != nil {
			return nil, err
		}
	}
	outsock, ok := mp.(*net.TCPConn)
	if !ok {
		panic("failed to cast tcp connection")
	}
	outsock.SetNoDelay(true)
	rs := newRawStream(mp, tgcrypt.Full)
	mps := NewMiddleProxyStream(rs, client, outsock, mp, addTag, cliProtocol)
	if err != nil {
		return nil, err
	}
	return mps, nil
}

// only direct connections supported
func connectBoth(url4, url6 string) (c net.Conn, err error) {
	var err6, err4 error
	if url6 != "" {
		c, err6 = net.DialTimeout("tcp", url6, time.Second*5)
		if err6 == nil {
			return c, nil
		}
	}
	c, err4 = net.DialTimeout("tcp", url4, time.Second*5)
	if err4 == nil {
		return c, nil
	}
	tcp, ok := c.(*net.TCPConn)
	if ok {
		tcp.SetNoDelay(false)
	}
	return nil, fmt.Errorf("can't connect to middle proxy %w %w", err4, err6)
}

func NewMiddleProxyStream(mpStream dataStream, client, out, mp net.Conn, addTag []byte, protocolCli uint8) *MiddleProxyStream {
	outa := out.LocalAddr() // client address
	oatcp, ok := outa.(*net.TCPAddr)
	if !ok {
		panic("client is not a socket")
	}
	mpa := mp.RemoteAddr() // outbound address
	mptcp, ok := mpa.(*net.TCPAddr)
	if !ok {
		panic("out is not a socket")
	}
	ctx := tgcrypt.NewMiddleCtx(oatcp.AddrPort(), mptcp.AddrPort(), addTag)
	seq := uint32(0)
	seq -= 2
	clia := client.LocalAddr()
	clitcp, ok := clia.(*net.TCPAddr)
	if !ok {
		panic("client is not a socket")
	}
	return &MiddleProxyStream{
		initiated: false,
		protoCli:  protocolCli,
		cliAddr:   clitcp.AddrPort(),
		seq:       seq,
		ctx:       ctx,
		mSock:     mpStream,
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
	initialMsgData = append(initialMsgData, tgcrypt.RpcNonceTag[:]...)
	secret := mpm.GetSecret()
	keySelector := secret[:4]
	initialMsgData = append(initialMsgData, keySelector...) // key selector
	initialMsgData = append(initialMsgData, tgcrypt.RpcCryptoAesTag[:]...)
	timestampCli := binary.LittleEndian.AppendUint32([]byte{}, uint32((time.Now().Unix())%0x100000000))
	initialMsgData = append(initialMsgData, timestampCli...) // crypto timestamp
	initialMsgData = append(initialMsgData, m.ctx.CliNonce[:]...)
	msg := &message{
		data:     initialMsgData,
		quickack: false,
		seq:      m.seq,
	}
	mpBlockStream := newRawStream(m.mSock, tgcrypt.Full)
	mpMsgStream := newMsgBlockStream(mpBlockStream, 32)
	err = mpMsgStream.WriteMsg(msg)
	if err != nil {
		return fmt.Errorf("failed to send initial message: %w", err)
	}
	m.seq++
	msg, err = mpMsgStream.ReadMsg()
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
	copy(m.mpNonce[:], msg.data[16:32])
	// TODO: check timestamp
	if !bytes.Equal(rpcType, tgcrypt.RpcNonceTag[:]) ||
		!bytes.Equal(rpcKeySelector, keySelector) ||
		!bytes.Equal(rpcSchema, tgcrypt.RpcCryptoAesTag[:]) {
		return fmt.Errorf("invalid initial reply")
	}
	m.ctx.SetObf(m.mpNonce[:], timestampCli, secret)
	m.mDataStream = newMsgBlockStream(newBlockStream(m.mSock, m.ctx.Obf), 32) //m.ctx.Obf.BlockSize())
	handshakeMsg := make([]byte, 0, 32)
	handshakeMsg = append(handshakeMsg, tgcrypt.RpcHandShakeTag[:]...)
	handshakeMsg = append(handshakeMsg, 0, 0, 0, 0)                //rpc flags
	handshakeMsg = append(handshakeMsg, []byte("IPIPPRPDTIME")...) //SENDER_PID
	handshakeMsg = append(handshakeMsg, []byte("IPIPPRPDTIME")...) //PEER_PID
	//fmt.Println(hex.EncodeToString(handshakeMsg))
	msg = &message{
		data:     handshakeMsg,
		quickack: false,
		seq:      m.seq,
	}
	err = m.mDataStream.WriteMsg(msg)
	if err != nil {
		return fmt.Errorf("failed to send encrypted handshake message: %w", err)
	}
	m.seq++
	msg, err = m.mDataStream.ReadMsg()
	if err != nil {
		fmt.Printf("failed to read encrypted handshake reply: %v\n", err)
		return fmt.Errorf("failed to read encrypted reply: %w", err)
	}
	if len(msg.data) != 32 {
		return fmt.Errorf("invalid encrypted handshake reply length: %d", len(msg.data))
	}
	if !bytes.Equal(msg.data[:4], tgcrypt.RpcHandShakeTag[:]) ||
		!bytes.Equal(msg.data[20:32], []byte("IPIPPRPDTIME")) {
		return fmt.Errorf("bad encrypted rpc handshake answer")
	}
	// fill rest fields
	rand.Read(m.connId[:])
	return nil
}

func (m *MiddleProxyStream) ReadSrvMsg() (*message, error) {
	msg, err := m.mDataStream.ReadMsg()
	if err != nil {
		fmt.Printf("failed to read message: %v\n", err)
		return nil, fmt.Errorf("failed to read message: %w", err)
	}
	if len(msg.data) < 4 {
		return nil, fmt.Errorf("wrong message received")
	} else if bytes.Equal(msg.data[:4], tgcrypt.RpcProxyAnsTag[:]) && len(msg.data) > 16 {
		newmsg := message{
			data:     msg.data[16:],
			quickack: false,
		}
		return &newmsg, nil
	} else if bytes.Equal(msg.data[:4], tgcrypt.RpcSimpleAckTag[:]) && len(msg.data) >= 16 {
		newmsg := message{
			data:     msg.data[12:16],
			quickack: true,
		}
		return &newmsg, nil
	} else if bytes.Equal(msg.data[:4], tgcrypt.RpcCloseExtTag[:]) {
		fmt.Printf("End of server stream")
		return nil, fmt.Errorf("end of server stream")
	} else if bytes.Equal(msg.data[:4], tgcrypt.RpcUnknown[:]) {
		newmsg := message{
			data: nil,
		}
		return &newmsg, nil
	} else {
		fmt.Printf("Msg not parsed\n")
		return nil, fmt.Errorf("msg not parsed")
	}
}

func (m *MiddleProxyStream) WriteSrvMsg(msg *message) error {
	var flags uint32
	flags = tgcrypt.FlagHasAdTag | tgcrypt.FlagMagic | tgcrypt.FlagExtNode2
	switch m.protoCli {
	case tgcrypt.Abridged:
		flags |= tgcrypt.FlagAbbridged
	case tgcrypt.Intermediate:
		flags |= tgcrypt.FlagIntermediate
	case tgcrypt.Padded:
		flags |= tgcrypt.FlagIntermediate | tgcrypt.FlagPad
	default:
		return fmt.Errorf("unknown client protocol: %d", m.protoCli)
	}
	if msg.quickack {
		flags |= tgcrypt.FlagQuickAck
	}
	if bytes.Equal(msg.data[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		flags |= tgcrypt.FlagNotEncrypted
	}
	fullmsg := make([]byte, 0, 48+len(msg.data))
	fullmsg = append(fullmsg, tgcrypt.RpcProxyReqTag[:]...)
	fullmsg = binary.LittleEndian.AppendUint32(fullmsg, flags)
	fullmsg = append(fullmsg, m.connId[:]...)
	// TODO: option for obfuscation
	ip6 := m.cliAddr.Addr().As16()
	if m.cliAddr.Addr().Is4() {
		ip6[10] = 0xff
		ip6[11] = 0xff
	}
	// ip6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	fullmsg = append(fullmsg, ip6[:]...)
	fullmsg = binary.LittleEndian.AppendUint32(fullmsg, uint32(m.ctx.MP.Port()))
	ip6Cli := m.ctx.Out.Addr().As16()
	if m.ctx.Out.Addr().Is4() {
		ip6Cli[10] = 0xff
		ip6Cli[11] = 0xff
	}
	//ip6Cli := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	fullmsg = append(fullmsg, ip6Cli[:]...)
	fullmsg = binary.LittleEndian.AppendUint32(fullmsg, uint32(m.ctx.Out.Port()))
	fullmsg = append(fullmsg, tgcrypt.ExtraSize[:]...)
	fullmsg = append(fullmsg, tgcrypt.ProxyTag[:]...)
	fullmsg = append(fullmsg, uint8(len(m.ctx.AdTag)))
	fullmsg = append(fullmsg, m.ctx.AdTag...)
	fullmsg = append(fullmsg, 0, 0, 0) //allign bytes
	data := msg.data[:len(msg.data)-len(msg.data)%4]
	fullmsg = append(fullmsg, data...) //trim padded message

	wrappedMsg := message{
		data:     fullmsg,
		quickack: false,
		seq:      m.seq,
	}
	err := m.mDataStream.WriteMsg(&wrappedMsg)
	if err != nil {
		fmt.Printf("failed to send message: %v\n", err)
		return fmt.Errorf("failed to send message: %w", err)
	}
	m.seq++
	return nil
}

func (s *MiddleProxyStream) CloseStream() error {
	if s.mDataStream == nil {
		return nil
	} else {
		return s.mDataStream.CloseStream()
	}
}
