package hippo

import (
	"encoding/json"
	"io/ioutil"
)

func fromFile(fn string, key interface{}) error {
	buf, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}

	return fromBytes(buf, key)
}

func fromBytes(buf []byte, key interface{}) error {
	return json.Unmarshal(buf, key)
}


func toFile(key interface{}, fn string) error {
	buf, err := toBytes(key)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(fn, buf, 0644)
}

func toBytes(key interface{}) ([]byte,error) {
	return json.Marshal(key)	
}


