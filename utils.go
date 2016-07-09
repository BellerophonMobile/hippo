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

	return json.Unmarshal(buf, key)
}

func toFile(key interface{}, fn string) error {
	buf, err := json.Marshal(key)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(fn, buf, 0644)
}
