package vtscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/valyala/fasthttp"
)

type Vtscan struct {
	email  string
	token  string
	server string

	merr sync.Mutex
	err  error //last error

	m    sync.Mutex
	conn net.Conn
}

type ServerAnswer struct {
	Status  string
	Message string
	Record  struct {
		Token string
	}
}

/*
	Register client instance by email
	server_ip - only for raw socket data, if paid
*/
func Register(email string, server_ip string) (*Vtscan, error) {
	if email == "" {
		return nil, fmt.Errorf("incorrect email")
	}

	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	args.Add("email", email)

	var dst []byte
	status, body, err := fasthttp.Post(dst, "https://virustotalscan.com/api/client/register", args)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("Failed with status: %d, body: %s", status, string(body))
	}

	var ret ServerAnswer
	err = json.Unmarshal(body, &ret)
	if err != nil {
		return nil, err
	}

	if ret.Status != "success" {
		return nil, fmt.Errorf("Failed with %s", ret.Message)
	}

	if len(ret.Record.Token) == 0 {
		return nil, errors.New("Invalid token. Contact support.")
	}

	return &Vtscan{
		email:  email,
		token:  ret.Record.Token,
		server: server_ip,
	}, nil
}

func (v *Vtscan) SocketIsConnected() bool {
	v.m.Lock()
	b := v.conn != nil
	v.m.Unlock()
	return b
}

func (v *Vtscan) setLastError(err error) {
	v.merr.Lock()
	defer v.merr.Unlock()
	v.err = err
}

func (v *Vtscan) LastError() error {
	v.merr.Lock()
	defer v.merr.Unlock()
	return v.err
}

func (v *Vtscan) Token() string {
	return v.token
}

/*
	Sends to the server file or buffer to scan for known signatures.

	Based on server answer:
		200 OK 		- nothing found

		403 EXPIRED - token is expired
		403 DENIED  - access denied

		200 SUSPICIOUS 	- Suspicious file
		200 FOUND 	- Signature found

		415 INCORRECTBUFFER - Incorrect buffer (too huge or absent)
		500 ERROR 	- Some error on server

	Returns:
		true if something found with description
*/
func (v *Vtscan) Check(buf []byte) (bool, error) {
	args := fasthttp.AcquireArgs()
	args.Add("t", v.token)
	args.AddBytesV("b", buf)

	var dst []byte
	status, body, err := fasthttp.Post(dst, "https://virustotalscan.com/api/check", args)
	if err != nil {
		return false, err
	}

	switch status {
	case 200:
		switch string(body) {
		case "OK": //nothing found
			return false, nil
		case "SUSPICIOUS", "FOUND": //"Something found. Details are in your account."
			return true, nil
		}
	case 415:
		return false, fmt.Errorf("Incorrect buffer")
	case 500:
		return false, fmt.Errorf("Server error")
	default:
		return false, fmt.Errorf("Unknown server answer: %d. Update lib.", status)
	}
	return false, nil
}
