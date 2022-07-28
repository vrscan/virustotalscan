package vtscan

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"
)

func (v *Vtscan) startSocketSender() {
	dialer := net.Dialer{
		Timeout:   time.Second * 20,
		KeepAlive: time.Second * 15,
	}

	go func() {
		for {
			v.m.Lock()
			if v.conn != nil { //is conn still alive?
				v.m.Unlock()
				time.Sleep(time.Minute)
				continue
			}
			v.m.Unlock()

			//conn is dead, reconnect

			conn, err := dialer.Dial("tcp", v.server+":82")

			if err != nil {
				v.setLastError(err)
				time.Sleep(time.Minute)
				continue
			}

			v.m.Lock()
			v.conn = conn
			v.m.Unlock()

			v.conn.SetDeadline(time.Now().Add(time.Minute))

			//токен
			var tbuf = []byte(v.token)
			tbb := bytes.NewBuffer(tbuf)
			_, err = io.CopyN(v.conn, tbb, 32)
			if err != nil {
				v.setLastError(err)
				time.Sleep(time.Minute)
				continue
			}

			time.Sleep(time.Minute)
		}
	}()
}

/*
	Sends to the server file or buffer to scan for known signatures.

	Returns:
		true if something found with description
*/
func (v *Vtscan) FastCheck(data []byte) (bool, error) {
	v.m.Lock()
	if v.conn == nil {
		v.m.Unlock()
		return false, fmt.Errorf("connection is closed")
	}
	v.m.Unlock()

	var dataLen [4]byte
	var dsizeBuf = make([]byte, 0, 4)
	dsize := bytes.NewBuffer(dsizeBuf)

	v.conn.SetWriteDeadline(time.Now().Add(time.Minute))

	if len(data) > 1000 || len(data) < 10 {
		return false, fmt.Errorf("incorrect data len")
	}

	//send datalen
	dl := len(data)
	dataLen[0] = byte(dl & 0xFF)
	dataLen[1] = byte((dl >> 8) & 0xFF)
	dataLen[2] = byte((dl >> 16) & 0xFF)
	dataLen[3] = byte((dl >> 24) & 0xFF)
	dsize.Reset()
	dsize.Write(dataLen[:])

	_, err := io.CopyN(v.conn, dsize, 4)
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
	var buf []byte
	bw := bytes.NewBuffer(buf)

	v.conn.SetReadDeadline(time.Now().Add(time.Minute))
	n, err := io.CopyN(bw, v.conn, 1)
	if n > 1 {
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
	return bw.Bytes()[0] == 8, nil
}
