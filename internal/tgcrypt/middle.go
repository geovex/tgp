package tgcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"net/netip"
)

var (
	RpcNonceTag     = [4]byte{0xaa, 0x87, 0xcb, 0x7a}
	RpcCryptoAesTag = [4]byte{0x01, 0, 0, 0}
	RpcHandShakeTag = [4]byte{0xf5, 0xee, 0x82, 0x76}
	RpcProxyAnsTag  = [4]byte{0x0d, 0xda, 0x03, 0x44}
	RpcCloseExtTag  = [4]byte{0xa2, 0x34, 0xb6, 0x5e}
	RpcSimpleAckTag = [4]byte{0x9b, 0x40, 0xac, 0x3b}
	RpcUnknown      = [4]byte{0xdf, 0xa2, 0x30, 0x57}
	RpcProxyReqTag  = [4]byte{0xee, 0xf1, 0xce, 0x36}
	ProxyTag        = [4]byte{0xae, 0x26, 0x1e, 0xdb}
	ExtraSize       = [4]byte{0x18, 0x00, 0x00, 0x00}
	PaddingFiller   = [4]byte{0x4, 0, 0, 0}
)

const (
	FlagNotEncrypted uint32 = 0x02
	FlagHasAdTag     uint32 = 0x8
	FlagMagic        uint32 = 0x1000
	FlagExtNode2     uint32 = 0x20000
	FlagPad          uint32 = 0x8000000
	FlagIntermediate uint32 = 0x20000000
	FlagAbbridged    uint32 = 0x40000000
	FlagQuickAck     uint32 = 0x80000000
)

const RpcNonceLen = 16

type RpcNonce [RpcNonceLen]byte

const AddTagLength = 16

type MpCtx struct {
	reader, writer cipher.BlockMode
}

func (m *MpCtx) EncryptBlocks(buf []byte) {
	if len(buf)%m.writer.BlockSize() != 0 {
		panic("invalid block size")
	}
	m.writer.CryptBlocks(buf, buf)
}

func (m *MpCtx) DecryptBlocks(buf []byte) {
	if len(buf)%m.reader.BlockSize() != 0 {
		panic("invalid block size")
	}
	m.reader.CryptBlocks(buf, buf)
}

func (m *MpCtx) BlockSize() int {
	return m.reader.BlockSize()
}

type MiddleCtx struct {
	CliNonce RpcNonce
	AdTag    []byte
	Out      netip.AddrPort
	MP       netip.AddrPort
	Obf      *MpCtx
}

func NewMiddleCtx(
	ipOut netip.AddrPort,
	ipMP netip.AddrPort,
	adTag []byte,
) (m *MiddleCtx) {
	m = &MiddleCtx{
		Out:   ipOut,
		MP:    ipMP,
		AdTag: adTag,
		Obf:   nil,
	}

	_, err := rand.Read(m.CliNonce[:])
	if err != nil {
		panic(err)
	}
	return
}

// initialize obfuscator for MiddleCtx
func (m *MiddleCtx) SetObf(
	nonceSrv, tsCli, secret []byte,
) {
	var zero4 = []byte{0x00, 0x00, 0x00, 0x00}
	s := make([]byte, 0, 246)
	s = append(s, nonceSrv...)
	s = append(s, m.CliNonce[:]...)
	s = append(s, tsCli...)
	if m.MP.Addr().Is4() {
		ip := m.MP.Addr().As4()
		s = append(s, ip[3], ip[2], ip[1], ip[0])
	} else if m.MP.Addr().Is6() {
		s = append(s, zero4...)
	} else {
		panic("not supported address type")
	}
	s = binary.LittleEndian.AppendUint16(s, m.Out.Port())
	s = append(s, []byte("CLIENT")...)
	if m.Out.Addr().Is4() {
		ip := m.Out.Addr().As4()
		s = append(s, ip[3], ip[2], ip[1], ip[0])
	} else if m.Out.Addr().Is6() {
		s = append(s, zero4...)
	} else {
		panic("not supported address type")
	}
	s = binary.LittleEndian.AppendUint16(s, m.MP.Port())
	s = append(s, secret...)
	s = append(s, nonceSrv...)
	if m.Out.Addr().Is6() {
		ip6 := m.Out.Addr().As16()
		s = append(s, ip6[:]...)
	}
	if m.MP.Addr().Is6() {
		ip6 := m.MP.Addr().As16()
		s = append(s, ip6[:]...)
	}
	s = append(s, m.CliNonce[:]...)
	md := md5.Sum(s[1:])
	sha := sha1.Sum(s)
	key := append([]byte{}, md[:12]...)
	key = append(key, sha[:]...)
	iv := md5.Sum(s[2:])
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	toMPcipher := cipher.NewCBCEncrypter(block, iv[:])
	copy(s[42:48], []byte("SERVER"))
	md = md5.Sum(s[1:])
	sha = sha1.Sum(s)
	key = append([]byte{}, md[:12]...)
	key = append(key, sha[:]...)
	iv = md5.Sum(s[2:])
	block, err = aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	fromMPcipher := cipher.NewCBCDecrypter(block, iv[:])
	obf := MpCtx{
		reader: fromMPcipher,
		writer: toMPcipher,
	}
	m.Obf = &obf
}

func (m *MiddleCtx) EncryptBlock(buf []byte) {
	m.Obf.EncryptBlocks(buf)
}

func (m *MiddleCtx) DecryptBlock(buf []byte) {
	m.Obf.DecryptBlocks(buf)
}

func (m *MiddleCtx) BlockSize() int {
	return aes.BlockSize
}
