package hippo

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
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

func toBytes(key interface{}) ([]byte, error) {
	return json.Marshal(key)
}

func setbigint(data map[string]interface{}, label string, val *big.Int, bytelen int) {

	data[label] = base64.RawURLEncoding.EncodeToString(val.Bytes())

}

func getbigint(data map[string]interface{}, label string, bytelen int) (*big.Int, error) {

	val, ok := data[label]
	if !ok {
		return nil, fmt.Errorf("Missing %v component", label)
	}

	sval, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("%v component not a string", label)
	}

	b, err := base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return nil, err
	}

	var xx big.Int
	xx.SetBytes(b)
	return &xx, nil

}

func setpaddedbigint(data map[string]interface{}, label string, val *big.Int, bytelen int) {

	bytes := val.Bytes()
	pad := make([]byte, bytelen-len(bytes))
	data[label] = base64.RawURLEncoding.EncodeToString(append(pad, bytes...))

}

func getpaddedbigint(data map[string]interface{}, label string, bytelen int) (*big.Int, error) {

	val, ok := data[label]
	if !ok {
		return nil, fmt.Errorf("Missing %v component", label)
	}

	sval, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("%v component not a string", label)
	}

	b, err := base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return nil, err
	}

	if len(b) != bytelen {
		return nil, fmt.Errorf("Incorrect bit length")
	}

	var xx big.Int
	xx.SetBytes(b)
	return &xx, nil

}

func setint(data map[string]interface{}, label string, i int) {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, i)
	data[label] = base64.RawURLEncoding.EncodeToString(buf.Bytes())

}

func getint(data map[string]interface{}, label string) (int, error) {

	val, ok := data[label]
	if !ok {
		return 0, fmt.Errorf("Missing %v component", label)
	}

	sval, ok := val.(string)
	if !ok {
		return 0, fmt.Errorf("%v component not a string", label)
	}

	b, err := base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return 0, err
	}

	var ival int64
	err = binary.Read(bytes.NewReader(b), binary.BigEndian, &ival)
	if err != nil {
		return 0, err
	}

	return int(ival), nil

}
