package vtscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/MasterDimmy/zipologger"
)

/*
	Sends to the local server file or buffer to scan for known signatures.
	Its the fastest method for now

	Protocol:
	[16] connId:  google's UUID to determinate unique connection
	[1] dir: fcConnDir
	[8] packetNum: counter of sended packets
	[4] dl bytes: data len
	[dl]: data to check

	Returns:
		true if something found
		decription
*/
func helperCheck(connId []byte, dir fcConnDir, packetNum int64, data []byte) (bool, []byte) {
	if len(data) < 10 || len(data) > 10240 {
		return false, nil
	}

	conn := GetServerConn()

	if conn == nil {
		return false, nil
	}

	return conn.send(connId, dir, packetNum, data)
}

type serverConn struct {
	c net.Conn
	m sync.Mutex
}

// nil if no good connection
var GetServerConn = func() func() *serverConn {
	connLog := zipologger.GetLoggerBySuffix("vtlconn.log", "./logs/", 2, 2, 2, false)

	dialer := net.Dialer{
		Timeout:   time.Millisecond * 500,
		KeepAlive: time.Second * 15,
	}

	port := ":89"

	var sconn = &serverConn{}

	go func() {
		for {
			//just need 1 connection to be opened
			conn, err := dialer.Dial("tcp", port)
			if err != nil {
				connLog.Printf("error: %s", err.Error())
				time.Sleep(2 * time.Second) //retry to connect every 2 sec
				continue
			}

			sconn.setConn(conn)

			//conn ok, test conn every 5 sec
			for {
				if !sconn.pingpong() {
					sconn.Fail()
					connLog.Print("ping pong failed. reconnect.")
					break
				}

				time.Sleep(2 * time.Second)
			}
		}
	}()

	return func() *serverConn {
		return sconn
	}
}()

//set to fail, forces to reconnect
func (s *serverConn) Fail() {
	s.m.Lock()
	defer s.m.Unlock()
	s.c = nil
}

func (s *serverConn) setConn(c net.Conn) {
	s.m.Lock()
	defer s.m.Unlock()
	s.c = c
}

func (s *serverConn) Conn() net.Conn {
	s.m.Lock()
	defer s.m.Unlock()
	return s.c
}

var zeroConn = []byte(fmt.Sprintf("%16d", 0))
var ping = []byte("ping")

// true on success
func (s *serverConn) pingpong() bool {
	a, _ := s.send(zeroConn, 1, 1, ping)
	return a
}

//result
//description
func (s *serverConn) send(connId []byte, dir fcConnDir, packetNum int64, data []byte) (bool, []byte) {
	buf := bytesBufferPool.Get().(*bytes.Buffer)
	defer bytesBufferPool.Put(buf)

	s.m.Lock()
	defer s.m.Unlock()

	if s.c == nil {
		return false, nil
	}

	s.c.SetWriteDeadline(time.Now().Add(time.Second * 2))

	if len(connId) != 16 {
		panic("connId not 16 bytes len!")
		return false, nil //never here, but...
	}

	//send conn uid
	buf.Reset()
	buf.Write(connId)

	n, err := io.CopyN(s.c, buf, 16)
	if err != nil {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	//send data dir
	nw, err := s.c.Write([]byte{byte(dir)})
	if err != nil || nw != 1 {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	//packetNum
	pnb := make([]byte, 8)
	binary.LittleEndian.PutUint64(pnb, uint64(packetNum))

	buf.Reset()
	buf.Write(pnb)

	_, err = io.CopyN(s.c, buf, 8)
	if err != nil {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	//send data len
	dl := len(data)
	buf.Reset()
	buf.Write([]byte{
		byte(dl & 0xFF),
		byte((dl >> 8) & 0xFF),
		byte((dl >> 16) & 0xFF),
		byte((dl >> 24) & 0xFF),
	})

	_, err = io.CopyN(s.c, buf, 4)
	if err != nil {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	//send data
	_, err = s.c.Write(data)
	if err != nil {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	//read response
	s.c.SetReadDeadline(time.Now().Add(time.Second * 2))
	n, err = io.CopyN(buf, s.c, 1)
	if n != 1 {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	if err != nil {
		s.c.Close()
		s.c = nil
		return false, nil
	}

	if buf.Len() == 0 {
		return false, nil
	}

	//0-not found, 1-found
	found := (buf.Bytes()[0] == 1 || buf.Bytes()[0] == 8)

	if found {
		//read description data len
		buf.Reset()
		n, err = io.CopyN(buf, s.c, 4)
		if n != 4 || err != nil {
			s.c = nil
			return false, nil
		}

		bb := buf.Bytes()
		bufLen := int64(bb[0]) + int64(bb[1])<<8 + int64(bb[2])<<16 + int64(bb[3])<<24

		if bufLen > 0 && bufLen < 10*1024 {
			//read description
			buf.Reset()
			n, err = io.CopyN(buf, s.c, bufLen)
			if n != 4 || err != nil {
				s.c = nil
				return false, nil
			}
		}

		return found, buf.Bytes()
	}

	return found, nil
}
