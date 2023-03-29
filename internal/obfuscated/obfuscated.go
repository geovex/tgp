package obfuscated

import (
	"bytes"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt"
)

type ObfuscatedHandler struct {
	config *config.Config
}

func NewObfuscatedHandler(cfg *config.Config) *ObfuscatedHandler {
	return &ObfuscatedHandler{
		config: cfg,
	}
}

func (o *ObfuscatedHandler) HandleObfuscated(stream net.Conn) (err error) {
	defer stream.Close()
	var initialPacket [tgcrypt.InitialHeaderSize]byte
	_, err = io.ReadFull(stream, initialPacket[:])
	if err != nil {
		return
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(tgcrypt.FakeTlsHeader)], tgcrypt.FakeTlsHeader[:]) {
		return o.handleFakeTls(initialPacket, stream)
	} else {
		return o.handleSimple(initialPacket, stream)
	}
}
