package obfuscated

import (
	"fmt"
	"io"
	"runtime"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o ObfuscatedHandler) handleSimple(initialPacket [tgcrypt.InitialHeaderSize]byte) (err error) {
	var cryptClient *tgcrypt.SimpleClientCtx
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
		cryptClient, err = tgcrypt.SimpleClientCtxFromHeader(initialPacket, userSecret)
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
	sa, su, sp, err := o.config.GetSocks5(*user)
	if err != nil {
		panic("user found, but GetUser not")
	}

	dcconn, err := dcConnectorFromSocks(sa, su, sp, o.config.GetAllowIPv6())
	if err != nil {
		return err
	}
	dcSock, err := dcconn.ConnectDC(cryptClient.Dc)
	if err != nil {
		return err
	}
	// cryptDc, err := tgcrypt.DcCtxNew(cryptClient.Dc, cryptClient.Protocol)
	// if err != nil {
	// 	return err
	// }
	dcStream, err := LoginDC(dcSock, cryptClient.Protocol)
	if err != nil {
		return err
	}
	defer dcStream.Close()
	clientStream := NewSimpleStream(o.client, cryptClient)
	defer clientStream.Close()
	_, _ = transceiveStreams(clientStream, dcStream)
	//err1, err2 := transceiveStreams(clientStream, dcStream)
	//fmt.Printf("Client disconnected %s: %v %v \n", *user, err1, err2)
	return nil
}

func NewSimpleStream(client io.ReadWriteCloser, ctx *tgcrypt.SimpleClientCtx) *encDecStream {
	return newEncDecStream(client, ctx)
}
