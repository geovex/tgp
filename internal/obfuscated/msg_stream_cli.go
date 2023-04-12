package obfuscated

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (s *msgStream) ReadCliMsg() (m *message, err error) {
	quickack := false
	var msgbuf []byte
	var seq uint32
	var msgLen uint32
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		var l [4]byte
		// read length
		_, err = io.ReadFull(s.sock, l[:1])
		if err != nil {
			return
		}
		if l[0]&0x80 != 0 {
			quickack = false
			fmt.Printf("client read quickack abridged %x\n", l)
			l[0] &= 0x7f
		}
		if l[0] < 0x7f {
			msgLen = uint32(l[0])
		} else {
			_, err = io.ReadFull(s.sock, l[:3])
			if err != nil {
				return
			}
			msgLen = binary.LittleEndian.Uint32(l[:])
		}
		msgLen = msgLen * 4
		// read message
		msgbuf = make([]byte, msgLen)
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		_, err = io.ReadFull(s.sock, msgbuf)
		if err != nil {
			return
		}
	case tgcrypt.Intermediate, tgcrypt.Padded:
		// read length
		var l [4]byte
		_, err = io.ReadFull(s.sock, l[:])
		if err != nil {
			return
		}
		msgLen = binary.LittleEndian.Uint32(l[:])
		if msgLen&0x80000000 != 0 {
			quickack = true
			msgLen &= 0x7fffffff
		}
		// read message
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		msgbuf = make([]byte, msgLen)
		_, err = io.ReadFull(s.sock, msgbuf)
		if err != nil {
			return
		}
	case tgcrypt.Full:
		// read length
		var l [4]byte
		_, err = io.ReadFull(s.sock, l[:])
		if err != nil {
			return
		}
		msgLen := binary.LittleEndian.Uint32(l[:])
		if msgLen&0x80000000 != 0 {
			quickack = true
			msgLen &= 0x7fffffff
		}
		// read message
		if msgLen > tgcrypt.MaxPayloadSize+12 {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		rawmsg := make([]byte, msgLen)
		rawmsg = append(rawmsg, l[:]...)
		_, err = io.ReadFull(s.sock, rawmsg[4:])
		if err != nil {
			return
		}
		seq = binary.LittleEndian.Uint32(rawmsg[4:8])
		msg := rawmsg[8 : msgLen-4]
		crc := binary.LittleEndian.Uint32(rawmsg[msgLen-4:])
		//check crc
		crcreal := crc32.ChecksumIEEE(msg[:msgLen-4])
		if crc != crcreal {
			err = fmt.Errorf("bad crc: %x!= %x", crc, crcreal)
			return
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	if quickack {
		fmt.Printf("client read quickack\n")
	}
	m = &message{data: msgbuf, quickack: quickack, seq: seq}
	return
}

func (s *msgStream) WriteCliMsg(m *message) (err error) {
	sendmsg := make([]byte, 0, len(m.data)+20)
	if m.quickack {
		if s.sock.Protocol() == tgcrypt.Abridged {
			sendmsg = []byte{m.data[3], m.data[2], m.data[1], m.data[0]}
			fmt.Printf("client write quickack abridged %v\n", sendmsg[:4])
		} else {
			sendmsg = m.data
			fmt.Printf("client write quickack %v\n", sendmsg)
		}
		_, err = s.sock.Write(sendmsg)
		return
	}
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		l := uint32(len(m.data))
		if l%4 != 0 {
			return fmt.Errorf("message size not multiple of 4")
		}
		l = l / 4
		if l >= 0x7f {
			sendmsg = append(sendmsg, 0x7f)
			sendmsg = append(sendmsg, binary.LittleEndian.AppendUint32([]byte{}, l)[:3]...)
		} else {
			sendmsg = append(sendmsg, byte(l))
		}
		sendmsg = append(sendmsg, m.data...)
	case tgcrypt.Intermediate, tgcrypt.Padded:
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, uint32(len(m.data)))
		sendmsg = append(sendmsg, m.data...)
	case tgcrypt.Full:
		sendmsg = make([]byte, 0, len(m.data)+12)
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, uint32(len(m.data)))
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, m.seq)
		sendmsg = append(sendmsg, m.data...)
		crc := crc32.ChecksumIEEE(sendmsg)
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, crc)
	default:
		fmt.Printf("Cli unsupported protocol: %x\n", s.sock.Protocol())
		return fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	_, err = s.sock.Write(sendmsg)
	return
}
