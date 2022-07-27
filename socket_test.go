package vtscan

import (
	"io/ioutil"
	"testing"

	"github.com/vrscan/virustotalscan"
)

func Test_socketFastCheck(t *testing.T) {
	err := initTestConfig()
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	client, err := vtscan.Register(config.Email, config.Server)
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	tests := map[string]bool{
		"./testfiles/found.bin":   true,
		"./testfiles/nothing.bin": false,
	}

	for i := 0; i < 100; i++ {
		for file, _ := range tests {
			filebuf, err := ioutil.ReadFile(file)
			if err != nil {
				t.Fatal(err.Error())
				return
			}

			found, err := client.FastCheck(filebuf)
			if err != nil {
				t.Fatal(err.Error())
				return
			}

			t.Logf("found result: %t", found)
		}
	}
}
