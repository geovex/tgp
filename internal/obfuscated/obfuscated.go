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
	client net.Conn
	config *config.Config
}

func NewObfuscatedHandler(cfg *config.Config, client net.Conn) *ObfuscatedHandler {
	return &ObfuscatedHandler{
		config: cfg,
		client: client,
	}
}

func (o *ObfuscatedHandler) HandleObfuscated() (err error) {
	defer o.client.Close()
	var initialPacket [tgcrypt.InitialHeaderSize]byte
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
		return o.handleSimple(initialPacket)
	}
}

// redirect connection to fallback host in case of failed authentication
func (o *ObfuscatedHandler) handleFallBack(initialPacket []byte) (err error) {
	defer o.client.Close()
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
			n, err := o.client.Read(buf[:])
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
			_, err = o.client.Write(buf[:n])
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

func transceiveStreams(client io.ReadWriteCloser, dc io.ReadWriteCloser) (err1, err2 error) {
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		buf := make([]byte, 2048)
		for {
			size, err := client.Read(buf)
			if err != nil {
				readerJoinChannel <- err
				return
			}
			_, err = dc.Write(buf[:size])
			if err != nil {
				readerJoinChannel <- err
				return
			}
		}
	}()
	writerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		buf := make([]byte, 2048)
		for {
			size, err := dc.Read(buf)
			if err != nil {
				writerJoinChannel <- err
				return
			}
			_, err = client.Write(buf[:size])
			if err != nil {
				writerJoinChannel <- err
				return
			}
		}
	}()
	err1 = <-readerJoinChannel
	err2 = <-writerJoinChannel
	return
}
