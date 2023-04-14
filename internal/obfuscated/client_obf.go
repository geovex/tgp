package obfuscated

import (
	"encoding/hex"
	"fmt"
	"runtime"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o ClientHandler) handleObfClient(initialPacket [tgcrypt.NonceSize]byte) (err error) {
	var cliCtx *tgcrypt.ObfCtx
	var user *string
	for u := range o.config.IterateUsers() {
		runtime.Gosched()
		if tgcrypt.IsWrongNonce(initialPacket) {
			continue
		}
		userSecret, err := tgcrypt.NewSecretHex(u.Secret)
		if err != nil {
			continue
		}
		cliCtx, err = tgcrypt.ObfCtxFromNonce(initialPacket, userSecret)
		if err != nil {
			continue
		}
		// basic afterchecks
		if cliCtx.Dc > dcMaxIdx || cliCtx.Dc < -dcMaxIdx || cliCtx.Dc == 0 {
			continue
		}
		user = &u.Name
		fmt.Printf("Client connected %s, protocol: %x\n", *user, cliCtx.Protocol)
		break
	}
	if user == nil {
		return o.handleFallBack(initialPacket[:])
	}
	//connect to dc
	u, err := o.config.GetUser(*user)
	if err != nil {
		panic("user found, but GetUser not")
	}
	clientStream := newObfuscatedStream(o.client, cliCtx, nil, cliCtx.Protocol)
	defer clientStream.Close()
	if u.AdTag == nil {
		dcconn, err := dcConnectorFromSocks(u.Socks5, u.Socks5_user, u.Socks5_pass, o.config.GetAllowIPv6())
		if err != nil {
			return err
		}
		dcSock, err := dcconn.ConnectDC(cliCtx.Dc)
		if err != nil {
			return err
		}
		var dcStream dataStream
		if u.Obfuscate != nil && *u.Obfuscate {
			cryptDc := tgcrypt.DcCtxNew(cliCtx.Dc, cliCtx.Protocol)
			dcStream = ObfuscateDC(dcSock, cryptDc)
		} else {
			dcStream = LoginDC(dcSock, cliCtx.Protocol)
		}
		defer dcStream.Close()
		transceiveDataStreams(clientStream, dcStream)
	} else {
		mpm, err := getMiddleProxyManager(o.config)
		if err != nil {
			return fmt.Errorf("MiddleProxyManager not available: %v", err)
		}
		adTag, err := hex.DecodeString(*u.AdTag)
		if err != nil {
			return err
		}
		if len(adTag) != tgcrypt.AddTagLength {
			return fmt.Errorf("AdTag length %d is not %d", len(adTag), tgcrypt.AddTagLength)
		}
		mp, err := mpm.connect(cliCtx.Dc, o.client, cliCtx.Protocol, adTag)
		if err != nil {
			return err
		}
		defer mp.CloseStream()
		cliMsgStream := newMsgStream(clientStream)
		transceiveMsg(cliMsgStream, mp)
	}
	fmt.Printf("Client disconnected %s\n", *user)
	return nil
}
