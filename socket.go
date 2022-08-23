package vtscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

//start raw socket listener
func (v *Vtscan) StartSocketSender() {
	dialer := net.Dialer{
		Timeout:   time.Minute,
		KeepAlive: time.Second * 45,
	}

	go func() {
		for {
			if func() bool { //true on error
				v.m.Lock()
				defer v.m.Unlock()

				if v.conn != nil { //is conn still alive?
					return false ///no error
				}

				//conn is dead, reconnect
				conn, err := dialer.Dial("tcp", v.server+":82")
				if err != nil {
					v.setLastError(err)
					return true // error
				}

				conn.SetDeadline(time.Now().Add(time.Second * 30))

				abb := bytes.NewBufferString("")
				wr, err := io.CopyN(abb, conn, 2)
				if err != nil {
					v.setLastError(err)
					return true //error
				}
				if wr != 2 {
					v.setLastError(fmt.Errorf("incorrect data len: %d", wr))
					return true //error
				}

				//need to reregister client
				if abb.String() == "rg" {
					_, err := Register(v.email, v.server)
					if err != nil {
						v.setLastError(fmt.Errorf("error: %s", err.Error()))
					}
					return false //no error
				}

				//should be ok
				if abb.String() != "ok" {
					v.setLastError(fmt.Errorf("unknown answer: %s", abb.String()))
					return true //error
				}

				v.conn = conn
				v.conn.SetDeadline(time.Now().Add(time.Minute * 2))

				//токен
				var tbuf = []byte(v.token)
				tbb := bytes.NewBuffer(tbuf)
				_, err = io.CopyN(v.conn, tbb, 32)
				if err != nil {
					v.setLastError(err)
					return true //error
				}

				v.setLastError(nil)
				return false //no error
			}() {
				return
			}

			time.Sleep(time.Second)
		}
	}()

	//let him run
	time.Sleep(time.Second)
}

type fcConnDir byte

//direction of data moving
const (
	FC_CONN_READ  = fcConnDir(1)
	FC_CONN_WRITE = fcConnDir(2)
)

/*
	Sends to the server file or buffer to scan for known signatures.

	Protocol:

	[16] connId:  google's UUID to determinate unique connection
	[1] dir: fcConnDir
	[8] packetNum: counter of sended packets
	[4] dl bytes: data len
	[dl]: data to check

	Returns:
		true if something found with description
*/
func (v *Vtscan) FastCheck(connId []byte, dir fcConnDir, packetNum int64, data []byte) (bool, error) {
	if len(data) < 20 {
		return false, nil
	}

	v.m.Lock()
	defer v.m.Unlock()

	if v.conn == nil {
		return false, fmt.Errorf("connection is closed")
	}

	if fastYaraSearch(data) {
		return false, nil
	}

	buf := bytesBufferPool.Get().(*bytes.Buffer)
	defer bytesBufferPool.Put(buf)

	v.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))

	if len(data) > 1024*1024 || len(data) < 20 {
		return false, nil
	}

	//send uuid
	buf.Reset()
	buf.Write(connId)

	_, err := io.CopyN(v.conn, buf, 16)
	if err != nil {
		v.conn.Close()
		v.conn = nil
		return false, err
	}

	//send data dir
	nw, err := v.conn.Write([]byte{byte(dir)})
	if err != nil || nw != 1 {
		v.conn.Close()
		v.conn = nil
		return false, err
	}

	//packetNum
	pnb := make([]byte, 8)
	binary.LittleEndian.PutUint64(pnb, uint64(packetNum))

	buf.Reset()
	buf.Write(pnb)

	_, err = io.CopyN(v.conn, buf, 8)
	if err != nil {
		v.conn.Close()
		v.conn = nil
		return false, err
	}

	//send datalen
	dl := len(data)
	buf.Reset()
	buf.Write([]byte{
		byte(dl & 0xFF),
		byte((dl >> 8) & 0xFF),
		byte((dl >> 16) & 0xFF),
		byte((dl >> 24) & 0xFF),
	})

	_, err = io.CopyN(v.conn, buf, 4)
	if err != nil {
		v.conn.Close()
		v.conn = nil
		return false, err
	}

	//send data
	_, err = v.conn.Write(data)
	if err != nil {
		v.conn.Close()
		v.conn = nil
		return false, err
	}

	//read response
	v.conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	n, err := io.CopyN(buf, v.conn, 1)
	if n != 1 {
		v.conn.Close()
		v.conn = nil
		return false, fmt.Errorf("incorrect response len")
	}

	if err != nil {
		v.conn.Close()
		v.conn = nil
		return false, err
	}

	//9 = nothing found
	//8 = dangerous packet
	return buf.Bytes()[0] == 8, nil
}
