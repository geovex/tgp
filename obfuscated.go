package main

import (
	"bytes"
	"io"
	"net"
)

func handleObfuscated(stream net.Conn, dcConn DCConnector, users *Users) (err error) {
	defer stream.Close()
	var initialPacket [initialHeaderSize]byte
	_, err = io.ReadFull(stream, initialPacket[:])
	if err != nil {
		return
	}
	//check for tls in handshake
	if bytes.Equal(initialPacket[0:len(fakeTlsHeader)], fakeTlsHeader[:]) {
		return handleFakeTls(initialPacket, stream, dcConn, users)
	} else {
		return handleSimple(initialPacket, stream, dcConn, users)
	}
}
