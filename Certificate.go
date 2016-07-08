package hippo

import (
	"encoding/json"
	"encoding/base64"	
)

type Subject struct {
	ID string
	PublicKey PublicKey
}

type Testament struct {

	ID string

	Subject Subject
	Claims map[string]interface{}

	Expires string
	
}

type Declaration struct {

	Claim string
	Signer string
	Signature Signature
	
}

type Chain []*Declaration
type Certificate struct {
	Declarations Chain
}

func NewTestament(subjectID string, subjectkey PublicKey) *Testament {

	x := new(Testament)
	x.Subject.ID = subjectID
	x.Subject.PublicKey = subjectkey

	return x

}

func UnpackTestament(b64 string) (*Testament,error) {

	bytes,err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return nil,err
	}

	var testament Testament
	err = json.Unmarshal(bytes, &testament)
	if err != nil {
		return nil,err
	}

	return &testament,nil
	
}

func (x *Testament) Sign(id string, signer Signer) (*Declaration,error) {

	b64,err := x.Base64()
	if err != nil {
		return nil,err
	}

	signature,err := signer.Sign([]byte(b64))
	if err != nil {
		return nil,err
	}

	declaration := &Declaration{
		Claim: b64,
		Signer: id,
		Signature: signature,
	}

	return declaration,nil

}

func (x *Testament) Base64() (string,error) {

	j,err := json.Marshal(x)
	if err != nil {
		return "",err
	}
	
	return base64.URLEncoding.EncodeToString(j),nil
	
}
