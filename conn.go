package vtscan

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/MasterDimmy/zipologger"
	"github.com/google/uuid"
)

type ConnChecker struct {
	id        []byte   //conn uuid
	conn      net.Conn // original connection
	packetNum int64

	useLocalVThelper int32
	vtscan           *Vtscan

	flushCalled int32 //set 1 if true
	runnedTasks int64 //current read/writes goroutine count

	onalert func()
	onerror func(err error)

	logAll bool
	log    *zipologger.Logger
}

type Flusher struct {
	c *ConnChecker
}

// continue work after flush
func (f *Flusher) Run() {
	atomic.StoreInt32(&f.c.flushCalled, 0)
}

// flushes current checks to server and wait till em ends
// stop launch for new
// to continue checking call .Run()
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

// from conn to buffer
func (c *ConnChecker) Read(b []byte) (int, error) {
	n, e := c.conn.Read(b)
	if c.logAll {
		c.log.Printf("=> %s", string(b))
	}

	pnum := atomic.AddInt64(&c.packetNum, 1)

	if atomic.LoadInt32(&c.flushCalled) == 0 && n > 0 {
		var bc []byte
		bc = append(bc, b[:n]...)

		if atomic.LoadInt32(&c.useLocalVThelper) == 0 {
			if c.vtscan != nil {
				atomic.AddInt64(&c.runnedTasks, 1)
				go func() {
					defer atomic.AddInt64(&c.runnedTasks, -1)
					found, _, err := c.vtscan.FastCheck(c.id, FC_CONN_READ, pnum, bc)
					if found {
						c.onalert()
						return
					}
					if err != nil {
						c.onerror(err)
					}
				}()
			}
		} else {
			if a, _ := helperCheck(c.id, FC_CONN_READ, pnum, bc); a {
				return 0, nil
			}
		}

	}

	return n, e
}

// to conn
func (c *ConnChecker) Write(b []byte) (int, error) {
	if c.logAll {
		c.log.Printf("<= %s", string(b))
	}

	pnum := atomic.AddInt64(&c.packetNum, 1)

	if atomic.LoadInt32(&c.flushCalled) == 0 {
		var bc []byte
		bc = append(bc, b...)

		if atomic.LoadInt32(&c.useLocalVThelper) == 0 {
			if c.vtscan != nil {
				atomic.AddInt64(&c.runnedTasks, 1)
				go func() {
					defer atomic.AddInt64(&c.runnedTasks, -1)
					found, desc, err := c.vtscan.FastCheck(c.id, FC_CONN_WRITE, pnum, bc)
					if found {
						if len(desc) > 1 {
							c.conn.Write(desc)
						}
						return
					}
					if err != nil {
						c.onerror(err)
					}
				}()
			}
		} else {
			if a, b := helperCheck(c.id, FC_CONN_WRITE, pnum, bc); a {
				if len(b) > 0 {
					c.conn.Write(b)
				}
				return 0, nil
			}
		}
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
func NewDefferedConnChecker(useLocalVThelper bool, conn net.Conn, vtscan *Vtscan, onalert func(), onerror func(err error)) *ConnChecker {
	id := uuid.New()

	useLocalVThelper_i := int32(0)
	if useLocalVThelper {
		useLocalVThelper_i = 1
	}

	return &ConnChecker{
		useLocalVThelper: useLocalVThelper_i,
		id:               id[:],
		conn:             conn,
		vtscan:           vtscan,
		onalert:          onalert,
		onerror:          onerror,
	}
}

// net.Conn if needed
func (c *ConnChecker) Conn() net.Conn {
	return c
}
