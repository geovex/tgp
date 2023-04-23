package obfuscated

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/stats"
	"github.com/geovex/tgp/internal/tgcrypt"
)

type ClientHandler struct {
	statsHandle *stats.StatsHandle
	client      net.Conn
	config      *config.Config
	// available after handshake
	// TODO: decouple this
	user      *config.User
	cliCtx    *tgcrypt.ObfCtx
	cliStream dataStream
}

func NewClient(cfg *config.Config, statsHandle *stats.StatsHandle, client net.Conn) *ClientHandler {
	return &ClientHandler{
		statsHandle: statsHandle,
		config:      cfg,
		client:      client,
	}
}

func (o *ClientHandler) HandleClient() (err error) {
	defer o.client.Close()
	defer o.statsHandle.Close()
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
	o.statsHandle.SetState(stats.Fallback)
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

func (o *ClientHandler) processWithConfig() (err error) {
	s, ok := o.client.(*net.TCPConn)
	if !ok {
		panic("not a TCP connection")
	}
	o.statsHandle.SetConnected(s)
	if o.user.AdTag == nil { // no intermidiate proxy required
		dcConector, err := dcConnectorFromSocks(o.user.Socks5, o.user.Socks5_user, o.user.Socks5_pass, o.config.GetAllowIPv6())
		if err != nil {
			return err
		}
		sock, err := dcConector.ConnectDC(o.cliCtx.Dc)
		if err != nil {
			return fmt.Errorf("can't connect to DC %d: %w", o.cliCtx.Dc, err)
		}
		var dcStream dataStream
		if o.user.Obfuscate != nil && *o.user.Obfuscate {
			dcCtx := tgcrypt.DcCtxNew(o.cliCtx.Dc, o.cliCtx.Protocol)
			dcStream = ObfuscateDC(sock, dcCtx)
			o.statsHandle.SetState(stats.Obfuscated)
		} else {
			dcStream = LoginDC(sock, o.cliCtx.Protocol)
			o.statsHandle.SetState(stats.Obfuscated)
		}
		defer dcStream.Close()
		transceiveDataStreams(o.cliStream, dcStream)
	} else {
		mpm, err := getMiddleProxyManager(o.config)
		if err != nil {
			return err
		}
		adTag, err := hex.DecodeString(*o.user.AdTag)
		if err != nil {
			return err
		}
		mp, err := mpm.connect(o.cliCtx.Dc, o.client, o.cliCtx.Protocol, adTag)
		if err != nil {
			return err
		}
		defer mp.CloseStream()
		clientMsgStream := newMsgStream(o.cliStream)
		o.statsHandle.SetState(stats.Middleproxy)
		transceiveMsg(clientMsgStream, mp)
	}
	return nil
}
