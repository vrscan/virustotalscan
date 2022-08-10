package vtscan

import (
	"bytes"
	"net"
	"sync/atomic"
	"time"

	"github.com/MasterDimmy/zipologger"
)

type ConnChecker struct {
	conn   net.Conn // original connection
	vtscan *Vtscan
	buf    *bytes.Buffer

	flushCalled int32 //1 if true
	runnedTasks int64 //current read/writes

	onalert func()
	onerror func(err error)

	logAll bool
	log    *zipologger.Logger
}

type Flusher struct {
	c *ConnChecker
}

//continue work after flush
func (f *Flusher) Run() {
	atomic.StoreInt32(&f.c.flushCalled, 0)
}

//flushes current checks to server and wait till em ends
//stop launch for new
//to continue checking call .Run()
func (c *ConnChecker) Flush() *Flusher {
	atomic.StoreInt32(&c.flushCalled, 1)
	for {
		if atomic.LoadInt64(&c.runnedTasks) == 0 {
			return &Flusher{c: c}
		}
		time.Sleep(time.Millisecond * 100)
	}
}

func (c *ConnChecker) SetLogAll(b bool) {
	c.logAll = b
}

func (c *ConnChecker) SetLogger(log *zipologger.Logger) {
	c.log = log
}

//from conn to buffer
func (c *ConnChecker) Read(b []byte) (int, error) {
	n, e := c.conn.Read(b)
	if c.logAll {
		c.log.Printf("=> %s", string(b))
	}

	if atomic.LoadInt32(&c.flushCalled) == 0 {
		var bc []byte
		bc = append(bc, b...)
		atomic.AddInt64(&c.runnedTasks, 1)
		go func() {
			defer atomic.AddInt64(&c.runnedTasks, -1)
			found, err := c.vtscan.FastCheck(bc)
			if found {
				c.onalert()
				return
			}
			if err != nil {
				c.onerror(err)
			}
		}()
	}

	return n, e
}

//to conn
func (c *ConnChecker) Write(b []byte) (int, error) {
	if c.logAll {
		c.log.Printf("<= %s", string(b))
	}

	if atomic.LoadInt32(&c.flushCalled) == 0 {
		var bc []byte
		bc = append(bc, b...)
		atomic.AddInt64(&c.runnedTasks, 1)
		go func() {
			defer atomic.AddInt64(&c.runnedTasks, -1)
			found, err := c.vtscan.FastCheck(bc)
			if found {
				c.onalert()
				return
			}
			if err != nil {
				c.onerror(err)
			}
		}()
	}

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
