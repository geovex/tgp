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
	o.config.IterateUsers(func(u, s string) bool {
		runtime.Gosched()
		if tgcrypt.IsWrongNonce(initialPacket) {
			return false
		}
		userSecret, err := tgcrypt.NewSecretHex(s)
		if err != nil {
			return false
		}
		cliCtx, err = tgcrypt.ObfCtxFromNonce(initialPacket, userSecret)
		if err != nil {
			return false
		}
		// basic afterchecks
		if cliCtx.Dc > dcMaxIdx || cliCtx.Dc < -dcMaxIdx || cliCtx.Dc == 0 {
			return false
		}
		user = &u
		fmt.Printf("Client connected %s, protocol: %x\n", u, cliCtx.Protocol)
		return true
	})
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
	if u.Middleproxy == nil || !*u.Middleproxy {
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
		addTag, err := hex.DecodeString("00000000000000000000000000000000")
		if err != nil {
			panic(err)
		}
		mp, err := mpm.connect(cliCtx.Dc, o.client, cliCtx.Protocol, addTag)
		if err != nil {
			return err
		}
		defer mp.CloseStream()
		cliMsgStream := newMsgStream(clientStream)
		transceiveMsg(cliMsgStream, mp)
	}
	//transceiveMsgStreams(clientStream, dcStream)
	fmt.Printf("Client disconnected %s\n", *user)
	return nil
}
