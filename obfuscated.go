package main

import (
	"fmt"
	"io"
	"runtime"
)

const initialHeaderSize = 64

const (
	abridged     = 0xef
	intermediate = 0xee //0xeeeeeeee
	padded       = 0xdd //0xdddddddd
	full         = 0
)

type obfuscatedRouter struct {
	cryptClient       *obfuscatedClientCtx
	cryptDc           *dcCtx
	stream            io.ReadWriteCloser
	readerJoinChannel chan error
	writerJoinChannel chan error
	user              string
}

func obfuscatedRouterFromStream(stream io.ReadWriteCloser, dcConn DCConnector, users *Users) (r *obfuscatedRouter, err error) {
	var initialPacket [initialHeaderSize]byte
	_, err = io.ReadFull(stream, initialPacket[:])
	if err != nil {
		return nil, err
	}
	var cryptClient *obfuscatedClientCtx
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
		cryptClient, err = obfuscatedClientCtxFromHeader(initialPacket, secret)
		if err != nil {
			continue
		}
		// basic afterchecks
		if int(cryptClient.dc) > len(dc_ip4) || int(cryptClient.dc) < -len(dc_ip4) {
			continue
		}
		fmt.Printf("Client connected %s\n", u)
		user = u
		break
	}
	if cryptClient == nil {
		return nil, fmt.Errorf("user not found by secret")
	}
	//connect to dc
	dcConnection, err := dcConn.ConnectDC(int(cryptClient.dc))
	if err != nil {
		return nil, err
	}
	cryptDc, err := dcCtxFromClient(int(cryptClient.dc), cryptClient.protocol)
	if err != nil {
		return nil, err
	}
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer stream.Close()
		defer dcConnection.Close()
		_, err = dcConnection.Write(cryptDc.nonce[:])
		if err != nil {
			readerJoinChannel <- err
			return
		}
		buf := make([]byte, 2048)
		for {
			size, err := stream.Read(buf)
			if err != nil {
				//fmt.Printf("reader broken, size: %d, error: %s\n", size, err.Error())
				readerJoinChannel <- err
				return
			}
			cryptClient.decryptNext(buf[:size])
			// fmt.Printf("cl dec: %s\n", hex.EncodeToString(buf[:size]))
			cryptDc.encryptNext(buf[:size])
			_, err = dcConnection.Write(buf[:size])
			if err != nil {
				readerJoinChannel <- err
				return
			}
		}
	}()
	writerJoinChannel := make(chan error, 1)
	go func() {
		defer stream.Close()
		defer dcConnection.Close()
		buf := make([]byte, 2048)
		for {
			size, err := dcConnection.Read(buf)
			if err != nil {
				//fmt.Printf("writer broken, size: %d, error: %s\n", size, err.Error())
				writerJoinChannel <- err
				return
			}
			cryptDc.decryptNext(buf[:size])
			// fmt.Printf("dc dec: %s\n", hex.EncodeToString(buf[:size]))
			cryptClient.encryptNext(buf[:size])
			_, err = stream.Write(buf[:size])
			if err != nil {
				writerJoinChannel <- err
				return
			}
		}
	}()
	r = &obfuscatedRouter{
		cryptClient:       cryptClient,
		cryptDc:           cryptDc,
		stream:            stream,
		readerJoinChannel: readerJoinChannel,
		writerJoinChannel: writerJoinChannel,
		user:              user,
	}
	return r, nil
}

func (r obfuscatedRouter) Wait() {
	<-r.readerJoinChannel
	<-r.writerJoinChannel
}

func handleObfuscated(stream io.ReadWriteCloser, dcConn DCConnector, users *Users) error {
	r, err := obfuscatedRouterFromStream(stream, dcConn, users)
	if err != nil {
		return err
	}
	r.Wait()
	return nil
}
