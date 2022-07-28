package main

import (
	"bytes"
	"net"
	"time"

	vt "github.com/vrscan/virustotalscan"
)

type checkerConn struct {
	conn    net.Conn
	vtscan  *vt.Vtscan
	buf     *bytes.Buffer
	onalert func()
	onerror func(err error)
}

//from conn to buffer
func (c *checkerConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

//to conn
func (c *checkerConn) Write(b []byte) (int, error) {
	go func() {
		found, err := c.vtscan.FastCheck(b)
		if found {
			c.onalert()
			return
		}
		if err != nil {
			c.onerror(err)
		}
	}()
	return c.conn.Write(b)
}

func (c *checkerConn) Close() error {
	return c.conn.Close()
}

func (c *checkerConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *checkerConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *checkerConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *checkerConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *checkerConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

/*
	Creates MITM conn, called deffered alert if something found
*/
func NewDefferedConnChecker(conn net.Conn, vtscan *vt.Vtscan, onalert func(), onerror func(err error)) net.Conn {
	var b []byte
	buf := bytes.NewBuffer(b)
	return &checkerConn{
		conn:    conn,
		buf:     buf,
		vtscan:  vtscan,
		onalert: onalert,
		onerror: onerror,
	}
}
