package obfuscated

import (
	"bytes"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt"
)

func HandleObfuscated(stream net.Conn, dcConn DCConnector, users *config.Users) (err error) {
	defer stream.Close()
	var initialPacket [tgcrypt.InitialHeaderSize]byte
	_, err = io.ReadFull(stream, initialPacket[:])
	if err != nil {
		return
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(tgcrypt.FakeTlsHeader)], tgcrypt.FakeTlsHeader[:]) {
		return handleFakeTls(initialPacket, stream, dcConn, users)
	} else {
		return handleSimple(initialPacket, stream, dcConn, users)
	}
}
