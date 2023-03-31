package obfuscated

import (
	"bytes"
	"fmt"
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
	n, err := io.ReadFull(stream, initialPacket[:])
	if err != nil {
		if o.config.GetHost() != nil {
			return o.handleFallBack(initialPacket[:n], stream)
		} else {
			return fmt.Errorf("failed to read initial packet: %w", err)
		}
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(tgcrypt.FakeTlsHeader)], tgcrypt.FakeTlsHeader[:]) {
		return o.handleFakeTls(initialPacket, stream)
	} else {
		return o.handleSimple(initialPacket, stream)
	}
}

// redirect connection to fallback host in case of failed authentication
func (o *ObfuscatedHandler) handleFallBack(initialPacket []byte, client net.Conn) (err error) {
	defer client.Close()
	if o.config.GetHost() == nil {
		return fmt.Errorf("no fall back host")
	}
	fmt.Printf("redirect conection to fake host\n")
	dc, err := dcConnectorFromSocks(o.config.GetDefaultSocks(), o.config.GetAllowIPv6())
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
	reader := make(chan error, 1)
	writer := make(chan error, 1)
	go func() {
		var buf [2048]byte
		for {
			n, err := client.Read(buf[:])
			if err != nil {
				reader <- err
				return
			}
			_, err = host.Write(buf[:n])
			if err != nil {
				reader <- err
				return
			}
		}
	}()
	go func() {
		var buf [2048]byte
		for {
			n, err := host.Read(buf[:])
			if err != nil {
				writer <- err
				return
			}
			_, err = client.Write(buf[:n])
			if err != nil {
				writer <- err
				return
			}
		}
	}()
	<-reader
	<-writer
	return nil
}
