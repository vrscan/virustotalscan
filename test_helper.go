package vtscan

import (
	"encoding/json"
	"io/ioutil"
)

type testConfig struct {
	Email  string
	Server string
}

var config testConfig

func initTestConfig() error {
	b, err := ioutil.ReadFile("config.cfg")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &config)
}
