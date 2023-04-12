package obfuscated

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/geovex/tgp/internal/tgcrypt"
)

type blockStream struct {
	sock              dataStream
	ctx               *tgcrypt.MpCtx
	readBuf, writeBuf []byte
}

func newBlockStream(sock dataStream, ctx *tgcrypt.MpCtx) *blockStream {
	return &blockStream{
		sock:     sock,
		ctx:      ctx,
		readBuf:  []byte{},
		writeBuf: []byte{},
	}
}

func (s *blockStream) Initiate() error {
	return nil
}

func (s *blockStream) Protocol() uint8 {
	return tgcrypt.Full
}

func (s *blockStream) Read(b []byte) (n int, err error) {
	if len(s.readBuf) == 0 {
		buf := make([]byte, s.ctx.BlockSize())
		n, err = io.ReadFull(s.sock, buf)
		s.ctx.DecryptBlocks(buf)
		s.readBuf = append(s.readBuf, buf[:n]...)
	}
	n = copy(b, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return
}

func (s *blockStream) Write(b []byte) (n int, err error) {
	s.writeBuf = append(s.writeBuf, b...)
	for len(s.writeBuf) > s.ctx.BlockSize() {
		var written int
		s.ctx.EncryptBlocks(s.writeBuf[:s.ctx.BlockSize()])
		written, err = s.sock.Write(s.writeBuf[:s.ctx.BlockSize()])
		n += written
		if err != nil {
			return
		}
		s.writeBuf = s.writeBuf[s.ctx.BlockSize():]
	}
	return
}

func (s *blockStream) Close() error {
	return s.sock.Close()
}

type msgBlockStream struct {
	bs      dataStream
	padding int
}

func newMsgBlockStream(stream dataStream, padding int) *msgBlockStream {
	return &msgBlockStream{
		bs:      stream,
		padding: padding,
	}
}

func (s *msgBlockStream) ReadMsg() (m *message, err error) {
	l := tgcrypt.PaddingFiller
	for bytes.Equal(l[:], tgcrypt.PaddingFiller[:]) {
		_, err = io.ReadFull(s.bs, l[:])
		if err != nil {
			return
		}
	}
	msgLen := int(binary.LittleEndian.Uint32(l[:]))
	if msgLen < 12 || msgLen > tgcrypt.MaxPayloadSize+12 {
		err = fmt.Errorf("invalid message length: %d", msgLen)
		return
	}
	buf := make([]byte, msgLen)
	copy(buf, l[:])
	_, err = io.ReadFull(s.bs, buf[4:])
	if err != nil {
		return
	}
	//check crc
	crcRecv := binary.LittleEndian.Uint32(buf[msgLen-4:])
	crcCalc := crc32.ChecksumIEEE(buf[:msgLen-4])
	if crcRecv != crcCalc {
		err = fmt.Errorf("invalid message crc")
		return
	}
	seq := binary.LittleEndian.Uint32(buf[4:8])
	msg := buf[8 : msgLen-4]
	m = &message{
		data:     msg,
		seq:      seq,
		quickack: false,
	}
	// padding not present irl
	// rest := make([]byte, -(-msgLen % s.padding))
	// _, err = io.ReadFull(s.bs, rest)
	return
}

func (s *msgBlockStream) WriteMsg(m *message) (err error) {
	buf := make([]byte, 0, len(m.data)+12)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(m.data)+12))
	buf = binary.LittleEndian.AppendUint32(buf, m.seq)
	buf = append(buf, m.data...)
	crc := crc32.ChecksumIEEE(buf)
	buf = binary.LittleEndian.AppendUint32(buf, crc)
	padlen := -(-len(buf) % s.padding)
	padbuf := []byte{}
	for len(padbuf) < padlen {
		padbuf = append(padbuf, tgcrypt.PaddingFiller[:]...)
	}
	buf = append(buf, padbuf[:padlen]...)
	_, err = s.bs.Write(buf)
	return
}

func (s *msgBlockStream) CloseStream() error {
	return s.bs.Close()
}
