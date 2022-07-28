package vtscan

import (
	"io/ioutil"
	"testing"
)

func Test_All(t *testing.T) {
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

	tests := map[string]bool{
		"./testfiles/found.bin":   true,
		"./testfiles/nothing.bin": false,
	}

	for i := 0; i < 300; i++ {
		for file, ret := range tests {
			filebuf, err := ioutil.ReadFile(file)
			if err != nil {
				t.Fatal(err.Error())
				return
			}

			found, err := client.Check(filebuf)
			if err != nil {
				t.Fatal(err.Error())
			}

			if ret && !found {
				t.Fatal("Test file is not detected as suspicious")
			}

			if !ret && found {
				t.Fatal("Test file is detected as suspicious ")
			}
		}
	}
}
