package main

import (
	"fmt"
	"io"
	"net"
	"runtime"
)

func handleSimple(stream net.Conn, dcConn DCConnector, users *Users) (err error) {
	defer stream.Close()
	var initialPacket [initialHeaderSize]byte
	_, err = io.ReadFull(stream, initialPacket[:])
	if err != nil {
		return
	}
	var cryptClient *simpleClientCtx
	var user string
	for u, s := range users.users {
		runtime.Gosched()
		if isWrongNonce(initialPacket) {
			continue
		}
		secret, err := NewSecretHex(s)
		if err != nil {
			continue
		}
		cryptClient, err = simpleClientCtxFromHeader(initialPacket, secret)
		if err != nil {
			continue
		}
		// basic afterchecks
		if int(cryptClient.dc) > len(dc_ip4) || int(cryptClient.dc) < -len(dc_ip4) {
			continue
		}
		user = u
		fmt.Printf("Client connected %s, protocol: %x\n", user, cryptClient.protocol)
		break
	}
	if cryptClient == nil {
		return fmt.Errorf("user not found by secret")
	}
	//connect to dc
	dcConnection, err := dcConn.ConnectDC(int(cryptClient.dc))
	if err != nil {
		return err
	}
	cryptDc, err := dcCtxFromClient(int(cryptClient.dc), cryptClient.protocol)
	if err != nil {
		return err
	}
	transceiveSimple(stream, cryptClient, dcConnection, cryptDc)
	fmt.Printf("Client disconnected %s\n", user)
	return nil
}

func transceiveSimple(client net.Conn, cryptClient *simpleClientCtx, dc net.Conn, cryptDC *dcCtx) {
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		_, err := dc.Write(cryptDC.nonce[:])
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
			cryptClient.decryptNext(buf[:size])
			// fmt.Printf("cl dec: %s\n", hex.EncodeToString(buf[:size]))
			cryptDC.encryptNext(buf[:size])
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
			cryptDC.decryptNext(buf[:size])
			// fmt.Printf("dc dec: %s\n", hex.EncodeToString(buf[:size]))
			cryptClient.encryptNext(buf[:size])
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
