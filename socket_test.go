package vtscan

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"
)

func Test_socketFastCheck(t *testing.T) {
	err := initTestConfig()
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	client, err := Register(config.Email, config.Server)
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	for {
		if !client.SocketIsConnected() {
			time.Sleep(time.Second)
			continue
		}
		break
	}

	tests := map[string]bool{
		"./testfiles/found.bin":   true,
		"./testfiles/nothing.bin": false,
	}

	for i := 0; i < 50; i++ {
		for file, _ := range tests {
			filebuf, err := ioutil.ReadFile(file)
			if err != nil {
				t.Fatal(err.Error())
				return
			}

			found, err := client.FastCheck([]byte(fmt.Sprintf("%16d", i)), 1, 1, filebuf)
			if err != nil {
				t.Fatal(err.Error())
				return
			}

			t.Logf("found result: %t", found)
		}
	}
	t.Log("all checked")
}
