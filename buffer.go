package vtscan

import (
	"bytes"
	"sync"
)

var bytesBufferPool = sync.Pool{
	New: func() any {
		dsizeBuf := make([]byte, 0, 32)
		return bytes.NewBuffer(dsizeBuf)
	},
}
