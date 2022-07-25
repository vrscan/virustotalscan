package vtscan

import (
	"io/ioutil"
	"testing"
)

func Test_All(t *testing.T) {
	client, err := Register("your_registered@email.here")
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	tests := map[string]bool{
		"./testfiles/found.bin":   true,
		"./testfiles/nothing.bin": false,
	}

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
			t.Fatal("Test file is detected as suspicious")
		}
	}
}
