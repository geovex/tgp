package obfuscated

import (
	"fmt"
	"runtime"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o ClientHandler) handleObfClient(initialPacket [tgcrypt.NonceSize]byte) (err error) {
	var cryptClient *tgcrypt.ObfCtx
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
		cryptClient, err = tgcrypt.ObfCtxFromNonce(initialPacket, userSecret)
		if err != nil {
			return false
		}
		// basic afterchecks
		if cryptClient.Dc > dcMaxIdx || cryptClient.Dc < -dcMaxIdx || cryptClient.Dc == 0 {
			return false
		}
		user = &u
		fmt.Printf("Client connected %s, protocol: %x\n", u, cryptClient.Protocol)
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

	dcconn, err := dcConnectorFromSocks(u.Socks5, u.Socks5_user, u.Socks5_pass, o.config.GetAllowIPv6())
	if err != nil {
		return err
	}
	dcSock, err := dcconn.ConnectDC(cryptClient.Dc)
	if err != nil {
		return err
	}
	var dcStream dataStream
	if u.Obfuscate != nil && *u.Obfuscate {
		cryptDc := tgcrypt.DcCtxNew(cryptClient.Dc, cryptClient.Protocol)
		dcStream = ObfuscateDC(dcSock, cryptDc)
	} else {
		dcStream = LoginDC(dcSock, cryptClient.Protocol)
	}
	defer dcStream.Close()
	clientStream := newObfuscatedStream(o.client, cryptClient, &cryptClient.Nonce, cryptClient.Protocol)
	defer clientStream.Close()
	_, _ = transceiveDataStreams(clientStream, dcStream)
	//err1, err2 := transceiveStreams(clientStream, dcStream)
	//fmt.Printf("Client disconnected %s: %v %v \n", *user, err1, err2)
	// transceiveMsgStreams(clientStream, dcStream)
	fmt.Printf("Client disconnected %s\n", *user)
	return nil
}
