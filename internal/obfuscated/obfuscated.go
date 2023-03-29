package obfuscated

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt"
)

func HandleObfuscated(stream net.Conn, c *config.Config) (err error) {
	defer stream.Close()
	var initialPacket [tgcrypt.InitialHeaderSize]byte
	_, err = io.ReadFull(stream, initialPacket[:])
	if err != nil {
		return
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(tgcrypt.FakeTlsHeader)], tgcrypt.FakeTlsHeader[:]) {
		return handleFakeTls(initialPacket, stream, c)
	} else {
		return handleSimple(initialPacket, stream, c)
	}
}

func handleFallBack(initialPacket []byte, client net.Conn, cfg *config.Config) (err error) {
	defer client.Close()
	if cfg.GetHost() == nil {
		return fmt.Errorf("no fall back host")
	}
	fmt.Printf("redirect conection to fake host\n")
	dc, err := dcConnectorFromSocks(cfg.GetDefaultSocks())
	if err != nil {
		return
	}
	host, err := dc.ConnectHost(*cfg.GetHost())
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
