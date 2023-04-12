package obfuscated

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (s *msgStream) ReadSrvMsg() (m *message, err error) {
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		var l [4]byte
		// read length
		_, err = io.ReadFull(s.sock, l[:1])
		if err != nil {
			return
		}
		var msgLen uint32
		if l[0] < 0x7f {
			msgLen = uint32(l[0])
		} else {
			_, err = io.ReadFull(s.sock, l[1:4])
			if err != nil {
				return
			}
			if l[0]&0x80 != 0 {
				m = &message{[]byte{l[3], l[2], l[1], l[0]}, true, 0}
				fmt.Printf("server read quickack abridged %v\n", m.data)
				return
			}
			msgLen = binary.LittleEndian.Uint32(l[:]) >> 8
		}
		msgLen = msgLen * 4
		// read message
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		msg := make([]byte, msgLen)
		_, err = io.ReadFull(s.sock, msg)
		if err != nil {
			return
		}
		m = &message{msg, false, 0}
		return
	case tgcrypt.Intermediate, tgcrypt.Padded:
		// read length
		var l [4]byte
		_, err = io.ReadFull(s.sock, l[:])
		if err != nil {
			return
		}
		msgLen := binary.LittleEndian.Uint32(l[:])
		if msgLen&0x80000000 != 0 {
			fmt.Printf("server read quickack %d\n", msgLen)
			m = &message{l[:], true, 0}
			return
		}
		// read message
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		msg := make([]byte, msgLen)
		_, err = io.ReadFull(s.sock, msg)
		if err != nil {
			return
		}
		m = &message{msg, false, 0}
		return
	default:
		return nil, fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
}

func (s *msgStream) WriteSrvMsg(m *message) (err error) {
	sendmsg := make([]byte, 0, len(m.data)+20)
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
		if m.quickack {
			sendmsg[0] |= 0x80
			sendmsg = []byte{sendmsg[3], sendmsg[2], sendmsg[1], sendmsg[0]}
			fmt.Printf("server write quickack abridged %v\n", sendmsg)
		}
	case tgcrypt.Intermediate, tgcrypt.Padded:
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, uint32(len(m.data)))
		sendmsg = append(sendmsg, m.data...)
		if m.quickack {
			sendmsg[3] |= 0x80
			fmt.Printf("server write quickack %d\n", sendmsg[3])
		}
	default:
		fmt.Printf("Srv unsupported protocol: %x\n", s.sock.Protocol())
		return fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	fmt.Printf("msg write seq: %d hex: %s\n", m.seq, hex.EncodeToString(sendmsg))
	_, err = s.sock.Write(sendmsg)
	return
}
