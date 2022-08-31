package vtscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/MasterDimmy/golang-lruexpire"
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
*/
func VTHelperCheck(connId []byte, dir fcConnDir, packetNum int64, data []byte) bool {
	if len(data) < 10 || len(data) > 10240 {
		return false
	}

	conn := GetServerConn(string(connId))

	if conn == nil {
		return false
	}

	return conn.send(connId, dir, packetNum, data)
}

type serverConn struct {
	c net.Conn
	m sync.Mutex
}

// nil if no good connection
var GetServerConn = func() func(connId string) *serverConn {
	connLog := zipologger.GetLoggerBySuffix("vtlconn.log", "./logs/", 2, 2, 2, false)

	dialer := net.Dialer{
		Timeout:   time.Millisecond * 500,
		KeepAlive: time.Second * 15,
	}

	port := ":89"
	var conns, _ = lru.NewWithExpire(1000000, time.Minute*20)

	return func(connId string) *serverConn {
		existed, _ := conns.ContainsOrAdd(connId, &serverConn{})
		sconn_, _ := conns.Get(connId)

		if !existed && sconn_ != nil {
			//no pauses, establish new connection for future use
			go func() {
				//check connection to server for connId client outside conn
				for {
					//are we need this connection?
					sconn_, ok := conns.Peek(connId)
					if !ok {
						return
					}
					sconn := sconn_.(*serverConn)

					conn, err := dialer.Dial("tcp", port)
					if err != nil {
						connLog.Printf("%x | error: %s", connId, err.Error())
						time.Sleep(2 * time.Second) //retry to connect every 2 sec
						continue
					}

					sconn.setConn(conn)

					//conn ok, test conn every 5 sec
					for {
						//are we need this connection?
						_, ok := conns.Peek(connId)
						if !ok {
							conn.Close()
							return
						}

						if !sconn.pingpong() {
							sconn.Fail()
							connLog.Printf("%x | ping pong failed. reconnect.", connId)
							break
						}

						time.Sleep(5 * time.Second)
					}

				}
			}()

			return nil //no connection for now
		}
		return sconn_.(*serverConn)
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
	return s.send(zeroConn, 1, 1, ping)
}

func (s *serverConn) send(connId []byte, dir fcConnDir, packetNum int64, data []byte) bool {
	buf := bytesBufferPool.Get().(*bytes.Buffer)
	defer bytesBufferPool.Put(buf)

	s.m.Lock()
	defer s.m.Unlock()

	if s.c == nil {
		return false
	}

	s.c.SetWriteDeadline(time.Now().Add(time.Second))

	if len(connId) != 16 {
		panic("connId not 16 bytes len!")
		return false //never here, but...
	}

	//send conn uid
	buf.Reset()
	buf.Write(connId)

	n, err := io.CopyN(s.c, buf, 16)
	if err != nil {
		s.c.Close()
		s.c = nil
		return false
	}

	//send data dir
	nw, err := s.c.Write([]byte{byte(dir)})
	if err != nil || nw != 1 {
		s.c.Close()
		s.c = nil
		return false
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
		return false
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
		return false
	}

	//send data
	_, err = s.c.Write(data)
	if err != nil {
		s.c.Close()
		s.c = nil
		return false
	}

	//read response
	s.c.SetReadDeadline(time.Now().Add(time.Second))
	n, err = io.CopyN(buf, s.c, 1)
	if n != 1 {
		s.c.Close()
		s.c = nil
		return false
	}

	if err != nil {
		s.c.Close()
		s.c = nil
		return false
	}

	//0-not found, 1-found
	return buf.Bytes()[0] == 1
}
