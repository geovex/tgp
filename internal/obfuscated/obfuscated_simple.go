package obfuscated

import (
	"fmt"
	"net"
	"runtime"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o ObfuscatedHandler) handleSimple(initialPacket [tgcrypt.InitialHeaderSize]byte, stream net.Conn) (err error) {
	defer stream.Close()
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
		if int(cryptClient.Dc) > len(dc_ip4) || int(cryptClient.Dc) < -len(dc_ip4) {
			return false
		}
		user = &u
		fmt.Printf("Client connected %s, protocol: %x\n", u, cryptClient.Protocol)
		return true
	})
	if user == nil {
		return handleFallBack(initialPacket[:], stream, o.config)
	}
	//connect to dc
	s, err := o.config.GetSocks5(*user)
	if err != nil {
		panic("user found, but GetUser not")
	}

	dcconn, err := dcConnectorFromSocks(s, o.config.GetAllowIPv6())
	if err != nil {
		return err
	}
	dcConnection, err := dcconn.ConnectDC(cryptClient.Dc)
	if err != nil {
		return err
	}
	defer dcConnection.Close()
	cryptDc, err := tgcrypt.DcCtxNew(cryptClient.Dc, cryptClient.Protocol)
	if err != nil {
		return err
	}
	transceiveSimple(stream, cryptClient, dcConnection, cryptDc)
	fmt.Printf("Client disconnected %s\n", *user)
	return nil
}

func transceiveSimple(client net.Conn, cryptClient *tgcrypt.SimpleClientCtx, dc net.Conn, cryptDC *tgcrypt.DcCtx) {
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		_, err := dc.Write(cryptDC.Nonce[:])
		if err != nil {
			readerJoinChannel <- err
			return
		}
		buf := make([]byte, 2048)
		for {
			size, err := client.Read(buf)
			if err != nil {
				//fmt.Printf("reader broken, size: %d, error: %s\n", size, err.Error())
				readerJoinChannel <- err
				return
			}
			cryptClient.DecryptNext(buf[:size])
			// fmt.Printf("cl dec: %s\n", hex.EncodeToString(buf[:size]))
			cryptDC.EncryptNext(buf[:size])
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
				//fmt.Printf("writer broken, size: %d, error: %s\n", size, err.Error())
				writerJoinChannel <- err
				return
			}
			cryptDC.DecryptNext(buf[:size])
			// fmt.Printf("dc dec: %s\n", hex.EncodeToString(buf[:size]))
			cryptClient.EncryptNext(buf[:size])
			_, err = client.Write(buf[:size])
			if err != nil {
				writerJoinChannel <- err
				return
			}
		}
	}()
	<-readerJoinChannel
	<-writerJoinChannel
}
