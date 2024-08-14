package network_exchange

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/geovex/tgp/internal/tgcrypt_encryption"
)

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
