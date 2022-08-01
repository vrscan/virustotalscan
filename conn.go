package vtscan

import (
	"bytes"
	"log"
	"net"
	"time"
)

type checkerConn struct {
	conn    net.Conn // original connection
	vtscan  *Vtscan
	buf     *bytes.Buffer
	onalert func()
	onerror func(err error)

	logAll bool
	log    *log.Logger
}

func (c *checkerConn) SetLogAll(b bool) {
	c.logAll = b
}

//from conn to buffer
func (c *checkerConn) Read(b []byte) (int, error) {
	if c.logAll {
		c.log.Printf("[%s] => %s", c.conn.RemoteAddr().String(), string(b))
	}
	return c.conn.Read(b)
}

//to conn
func (c *checkerConn) Write(b []byte) (int, error) {
	if c.logAll {
		c.log.Printf("[%s] <= %s", c.conn.RemoteAddr().String(), string(b))
	}

	go func() {
		var bc []byte
		bc = append(bc, b...)
		found, err := c.vtscan.FastCheck(bc)
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
func NewDefferedConnChecker(conn net.Conn, vtscan *Vtscan, onalert func(), onerror func(err error), logAll bool) net.Conn {
	var b []byte
	buf := bytes.NewBuffer(b)
	return &checkerConn{
		conn:    conn,
		buf:     buf,
		vtscan:  vtscan,
		onalert: onalert,
		onerror: onerror,
		logAll:  logAll,
	}
}
