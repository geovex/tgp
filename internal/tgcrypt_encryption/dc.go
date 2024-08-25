package tgcrypt_encryption

import (
	"fmt"
	"math/rand"

	"github.com/geovex/tgp/internal/maplist"
)

// Context for obfuscation this-DC connection
type DcCtx struct {
	// Nonce is generated for this-dc connection
	Nonce    Nonce
	Protocol uint8
	obf      Obfuscator
}

func DcCtxNew(dc int16, protocol byte) (c *DcCtx) {
	header := genNonce()
	header[56] = protocol
	header[57] = protocol
	header[58] = protocol
	header[59] = protocol
	encKey := header[8:40]
	encIV := header[40:56]
	decReversed := decryptInit(header)
	decKey := decReversed[:32]
	decIV := decReversed[32:48]
	toDcStream := newAesStream(encKey, encIV)
	fromDcStream := newAesStream(decKey, decIV)
	var nonce [NonceSize]byte
	toDcStream.XORKeyStream(nonce[:], header[:])
	copy(nonce[:56], header[:56])
	c = &DcCtx{
		Nonce:    nonce,
		Protocol: protocol,
		obf: &obfuscatorCtx{
			reader: fromDcStream,
			writer: toDcStream,
		},
	}
	return
}

func (c *DcCtx) DecryptNext(buf []byte) {
	c.obf.DecryptNext(buf)
}

func (c *DcCtx) EncryptNext(buf []byte) {
	c.obf.EncryptNext(buf)
}

const DcMaxIdx = int16(5)

var DcIp4 = maplist.MapList[int16, string]{
	Data: map[int16][]string{
		1: {"149.154.175.50:443"},
		2: {"149.154.167.51:443", "95.161.76.100:443"},
		3: {"149.154.175.100:443"},
		4: {"149.154.167.91:443"},
		5: {"149.154.171.5:443"},
	},
}

var DcIp6 = maplist.MapList[int16, string]{
	Data: map[int16][]string{
		1: {"[2001:b28:f23d:f001::a]:443"},
		2: {"[2001:67c:04e8:f002::a]:443"},
		3: {"[2001:b28:f23d:f003::a]:443"},
		4: {"[2001:67c:04e8:f004::a]:443"},
		5: {"[2001:b28:f23f:f005::a]:443"},
	},
}

func GetDcAddr(dc int16) (ipv4, ipv6 string, err error) {
	if dc < 0 {
		dc = -dc
	}
	if dc < 1 || dc > DcMaxIdx {
		//return "", "", fmt.Errorf("invalid dc number %d", dc)
		//instead return random dc
		dc = int16(rand.Intn(int(DcMaxIdx)) + 1)
	}
	ipv4, _ = DcIp4.GetRandom(dc)
	ipv6, _ = DcIp6.GetRandom(dc)
	if ipv4 == "" && ipv6 == "" {
		// TODO may be panic here?
		return "", "", fmt.Errorf("invalid dc number %d", dc)
	}
	return ipv4, ipv6, nil
}
