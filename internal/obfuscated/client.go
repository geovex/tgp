package obfuscated

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt"
)

type ClientHandler struct {
	client net.Conn
	config *config.Config
}

func NewClient(cfg *config.Config, client net.Conn) *ClientHandler {
	return &ClientHandler{
		config: cfg,
		client: client,
	}
}

func (o *ClientHandler) HandleClient() (err error) {
	defer o.client.Close()
	var initialPacket tgcrypt.Nonce
	n, err := io.ReadFull(o.client, initialPacket[:])
	if err != nil {
		if o.config.GetHost() != nil {
			return o.handleFallBack(initialPacket[:n])
		} else {
			return fmt.Errorf("failed to read initial packet: %w", err)
		}
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(tgcrypt.FakeTlsHeader)], tgcrypt.FakeTlsHeader[:]) {
		return o.handleFakeTls(initialPacket)
	} else {
		return o.handleObfClient(initialPacket)
	}
}

// redirect connection to fallback host in case of failed authentication
func (o *ClientHandler) handleFallBack(initialPacket []byte) (err error) {
	defer o.client.Close()
	if o.config.GetHost() == nil {
		return fmt.Errorf("no fall back host")
	}
	fmt.Printf("redirect conection to fake host\n")
	sa, su, sp := o.config.GetDefaultSocks()
	dc, err := dcConnectorFromSocks(su, sa, sp, o.config.GetAllowIPv6())
	if err != nil {
		return
	}
	host, err := dc.ConnectHost(*o.config.GetHost())
	if err != nil {
		return
	}
	defer host.Close()
	_, err = host.Write(initialPacket)
	if err != nil {
		return
	}
	transceiveStreams(o.client, host)
	return nil
}