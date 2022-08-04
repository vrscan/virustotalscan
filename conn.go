package vtscan

import (
	"bytes"
	"net"
	"time"

	"github.com/MasterDimmy/zipologger"
)

type ConnChecker struct {
	conn    net.Conn // original connection
	vtscan  *Vtscan
	buf     *bytes.Buffer
	onalert func()
	onerror func(err error)

	logAll bool
	log    *zipologger.Logger
}

func (c *ConnChecker) SetLogAll(b bool) {
	c.logAll = b
}

func (c *ConnChecker) SetLogger(log *zipologger.Logger) {
	c.log = log
}

//from conn to buffer
func (c *ConnChecker) Read(b []byte) (int, error) {
	if c.logAll {
		c.log.Printf("=> %s", string(b))
	}
	return c.conn.Read(b)
}

//to conn
func (c *ConnChecker) Write(b []byte) (int, error) {
	if c.logAll {
		c.log.Printf("<= %s", string(b))
	}

	var bc []byte
	bc = append(bc, b...)
	go func() {
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

func (c *ConnChecker) Close() error {
	return c.conn.Close()
}

func (c *ConnChecker) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ConnChecker) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *ConnChecker) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *ConnChecker) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *ConnChecker) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

/*
	Creates MITM conn, called deffered alert if something found
*/
func NewDefferedConnChecker(conn net.Conn, vtscan *Vtscan, onalert func(), onerror func(err error)) net.Conn {
	var b []byte
	buf := bytes.NewBuffer(b)
	return &ConnChecker{
		conn:    conn,
		buf:     buf,
		vtscan:  vtscan,
		onalert: onalert,
		onerror: onerror,
	}
}
