package network_exchange

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/stats"
	"github.com/geovex/tgp/internal/tgcrypt_encryption"
)

type ClientHandler struct {
	statsHandle *stats.StatsHandle
	client      net.Conn
	config      *config.Config
	// available after handshake
	user      *config.User
	cliCtx    *tgcrypt_encryption.ObfCtx
	cliStream dataStream
}

func NewClient(cfg *config.Config, statsHandle *stats.StatsHandle, client net.Conn) *ClientHandler {
	return &ClientHandler{
		statsHandle: statsHandle,
		config:      cfg,
		client:      client,
	}
}

func (c *ClientHandler) HandleClient() (err error) {
	defer c.client.Close()
	defer c.statsHandle.Close()
	var initialPacket tgcrypt_encryption.Nonce
	n, err := io.ReadFull(c.client, initialPacket[:])
	if err != nil {
		return c.handleFallBack(initialPacket[:n])
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(tgcrypt_encryption.FakeTlsHeader)], tgcrypt_encryption.FakeTlsHeader[:]) {
		return c.handleFakeTls(initialPacket)
	} else {
		return c.handleObfClient(initialPacket)
	}
}

var errNoFallbackHost = errors.New("no fallback host")

// redirect connection to fallback host in case of failed authentication
func (c *ClientHandler) handleFallBack(initialPacket []byte) (err error) {
	defer c.client.Close()
	if c.config.GetHost() == nil {
		return errNoFallbackHost
	}
	c.statsHandle.SetState(stats.Fallback)
	fmt.Printf("redirect conection to fake host\n")
	sa, su, sp := c.config.GetDefaultSocks()
	dc, err := dcConnectorFromSocks(su, sa, sp, c.config.GetAllowIPv6())
	if err != nil {
		return
	}
	host, err := dc.ConnectHost(*c.config.GetHost())
	if err != nil {
		return
	}
	defer host.Close()
	_, err = host.Write(initialPacket)
	if err != nil {
		return
	}
	transceiveStreams(c.client, host)
	return nil
}

func (c *ClientHandler) processWithConfig() (err error) {
	s, ok := c.client.(*net.TCPConn)
	if !ok {
		panic("not a TCP connection")
	}
	c.statsHandle.SetConnected(s)
	var flags = stats.ConnectionFlags{}
	if c.user.AdTag == nil { // no intermidiate proxy required
		dcConector, err := dcConnectorFromSocks(c.user.Socks5, c.user.Socks5_user, c.user.Socks5_pass, c.config.GetAllowIPv6())
		if err != nil {
			return err
		}
		sock, err := dcConector.ConnectDC(c.cliCtx.Dc)
		if err != nil {
			return fmt.Errorf("can't connect to DC %d: %w", c.cliCtx.Dc, err)
		}
		var dcStream dataStream
		if c.user.Obfuscate != nil && *c.user.Obfuscate {
			dcCtx := tgcrypt_encryption.DcCtxNew(c.cliCtx.Dc, c.cliCtx.Protocol)
			dcStream = ObfuscateDC(sock, dcCtx)
			flags.Obfuscated = true
		} else {
			dcStream = LoginDC(sock, c.cliCtx.Protocol)
		}
		defer dcStream.Close()
		transceiveDataStreams(c.cliStream, dcStream)
	} else {
		mpm, err := getMiddleProxyManager(c.config)
		if err != nil {
			return err
		}
		adTag, err := hex.DecodeString(*c.user.AdTag)
		if err != nil {
			return fmt.Errorf("can't decode adTag (%s): %w", *c.user.AdTag, err)
		}
		middleProxyStream, err := mpm.connect(c.cliCtx.Dc, c.client, c.cliCtx.Protocol, adTag)
		if err != nil {
			return fmt.Errorf("can't connect to middle proxy: %w", err)
		}
		defer middleProxyStream.CloseStream()
		clientMsgStream := newMsgStream(c.cliStream)
		flags.MiddleProxy = true
		transceiveMsg(clientMsgStream, middleProxyStream)
	}
	c.statsHandle.OrFlags(flags)
	return nil
}
