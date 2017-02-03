package hippo

import (
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_RSA_Basic(t *testing.T) {
	test_pkcipher_basic(t, AlgorithmRSA_OAEP_2048)
}

func Test_RSA_JSON_Public(t *testing.T) {
	test_pkcipher_json_public(t, AlgorithmRSA_OAEP_2048)
}

func Test_RSA_JSON_Private(t *testing.T) {
	test_pkcipher_json_private(t, AlgorithmRSA_OAEP_2048)
}

func Test_RSA_Bogus_Key(t *testing.T) {

	data := []byte("Four score and seven years ago")

	keys, err := GeneratePKCipher(AlgorithmRSA_OAEP_2048)
	require.Nil(t, err)
	require.NotNil(t, keys)

	bogus, err := GeneratePKCipher(AlgorithmRSA_OAEP_2048)
	require.Nil(t, err)
	require.NotNil(t, keys)

	ciphertext, err := keys.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	cleartext, err := bogus.Decrypt(ciphertext)
	require.NotNil(t, err)
	require.Nil(t, cleartext)

}

func Test_RSA_Bogus_Data(t *testing.T) {

	data := []byte("Four score and seven years ago")

	keys, err := GeneratePKCipher(AlgorithmRSA_OAEP_2048)
	require.Nil(t, err)
	require.NotNil(t, keys)

	bogus, err := GeneratePKCipher(AlgorithmRSA_OAEP_2048)
	require.Nil(t, err)
	require.NotNil(t, keys)

	ciphertext, err := bogus.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	cleartext, err := keys.Decrypt(ciphertext)
	require.NotNil(t, err)
	require.Nil(t, cleartext)

}

func Test_RSA_WebCrypto_Out(t *testing.T) {

	data := []byte("Four score and seven years ago")

	cipherhex := "4584c2de75d47caab5f6d378a30c2a272e0a916a4261583aadbf68fe711011826cdb4884b3ae8cf1c68ee80a3b7b231f1194fa9ef02516e44fb7fd97eb0bbb090860645ad2b0472587975136e953b44a76a1039655a3d7beb57b0d6899ff9f76b191192c391bfb08a67fb2b6e9b081ba86c081457efedbbce0d814ee3a6294b801d4681bf7e26d97c042a674752646bcc8787dd8a2e78ff40ecda7058992e5caaa52587b9f2475c9d6875a6baa43a09814632c7bdf0b055b9042557ff6a050764e36307996acdc0bd44d12cfa111360b7ed5c4e4910ef091760f4e1b3900332051af64e71dccc13165d89849dec68b5ee18f739e06537bdeb1be7dd3de513b50"
	ciphertext, _ := hex.DecodeString(cipherhex)

	private := PrivateKey{
		Algorithm: AlgorithmRSA_OAEP_2048,
		Private: map[string]interface{}{
			"N":  "ptn0l0jHZEl7noMcM4qBqwhpeQw5RbcMLp02pYAz2kctjHyYBNWGhHcej4MQyE6nb4AFWhQFquNedMxr-ZWsItTtUEd56hR40w1iFqINW-HrH3JEfr6v1BhTViVSIoiGTDFznAFCV45EBW-iRmbHTV1iWNuYHKJ7dn2vfT6SU6fIHldywVeLXvvboWDy21WZtWy4ND9V49frB4rxRU0OVSeRALOnogNg-pwwjKpuuYSYxrRESu38T-APlH3rLW1cvCbzgYgQiyOLiQknbHAsAUCYbj8y3EWUrhM93D756BU_HGyjbSRIxpff6L9YmB39hAJ4hOAHJj4L8EaX-rYNvQ",
			"D":  "hGpXJbT5oQp8U_lDaVgTvlOnuQxNa5lwzpGwK7pJ7IIukN7UmomG_xu2IjjnGcDqOqAEH0_ii5N0hAcz7ditytrnF54SEAZ9OSnW3ZVwOqpZuhQqbdgRnKZNhQGLZKKqyk84q-eH6gqayyGkTHEG3Mwu38wutRLyHsByhFgjMsWdP-SBV6tI3PrRFYwgaSZMPjkAfy4B4_crOiMboqcowUstUAm8PuTxT3vAF-F0sBJvYsLXMxFw1mZBxxWLsIZcmonWndNSwHgKY8PhTs4Vf-ldbAjjmywrep0zgltyjYvxMUeWV4mqlUMdjQlskNXYA7nqodwbH44L26UP6mIEtQ",
			"Dp": "l87QTHMkruADUO6Ik2yinEdf2B1uhWxGUap0WnLpm0_cJxeSywEegtgK-Y1xx7T48eb9e3B13CvnP7C1Z4y434KJtcfwSFnFBut4ekA05jE721CvO-SZIjTCYfVuw7TAZpzwtzPNvc-zLMqKtCQ4bD6sOHEZJlKw5crSMxBqSQc",
			"Dq": "qENVEnpkRGU-8oIU0KpPhhmUfAAGfaMbTLMmgCBy9VcvmTjRTZLD0N1KYKvpqG2iRa5mUQGdd2ACM5JVBYgz53Wdae-5m7h2z_lts6YTk4TSKjidi-vQtJiQI8dxRph76SYDgPO_259BvE8loJ4R5EeiaygXsMuEu6__WpNVPa0",
			"Qi": "hQeyMuDl_JERfisKP9GETmEq_cD2AsY3QTCvmPfgES9QZtp65VzhO8JVQW_9e9EkcJ89J9NvN-Y9LMkJD6etrXNRq5Vjph-UPje_75t4CcBY0RB2Dnc0VFPLIAsPAgDyemjOyXtj8ICfV5EgnfqPcXIWuIofZ-40YyzX35uGuLY",
			"P":  "3a0B_3XsuH5GkEOW2kxGEqP3k_laUN0y1tPSpaxkOFc-sqKtOLbPP3ikyRQuu8dxcJz4Rgh18F6o6kX4nts6mSX3hpVOu8xC7EXWBGVdvFQt9E9Ya6rPspiy3oijGDAS3XhYI3tO47MMMTNrHmnEKwC3NOCtWhIN6Lb7v_iAUyc",
			"Q":  "wK_EHwYIfl139enBntIdb3Mf1EpWZLmos1mBNYDi1XzQmFcmGGftVhPt2QEOoPpCc1JQv0XWXjrI3JoF7ABdQVwkdp2rJng7g1xFcknpTSDZf-H5mMh0cpcyXE6AA3qjkIl4_q55uKhk93XOKvDvxdsCi1d_yOegxXwyrwVJVns",
			"E":  "AQAB",
		},
	}

	decrypter, err := NewDecrypter(private)
	require.Nil(t, err)
	require.NotNil(t, decrypter)

	cleartext, err := decrypter.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}

func Test_RSA_WebCrypto_In(t *testing.T) {

	data := []byte("Four score and seven years ago")

	privatejson := `
{"Algorithm":"rsa-oaep-2048","Private":{"D":"SRIhyAPkWdBAeysBC9TLdR6-BZ4zXCwMuNKv3eiPjL3_G9RhgOhwg5Bcg10fbDbOCvtu6yOgNLxgE_CWuIQj6wgi7D3QvvJLpOK9AB1mdGYrnJ6EmNqIq2W8xdlAJ8aK-j278g7uCO2pBwWdYvg1GMVbNWrv2sCm857xmMjn6eB3jtuzlTu0id9jaO9p4WN6bSh4QiDHF0zE6c2TAnwU58lbr7_d4XHBU3j12cPJgaN9alI4kkdZYr0LOo-Ax1QffQYjOG812r9txDxJ2dG2pGadIBJA_kSmD8C63Kq00j8mwhUytnD9lGz3Hji92EZV9BklN_CThjFYSlsKWerAoQ","Dp":"Qq7MASQK1DOcHKViArPUuzNgdxQHpjjtA87SCWyk11RdjvDLoN0LLXg0uzy7U3RvBB5Ow51Rmj5PK2xUhohI_vGBMqvYoh2ySD2SxvvRMcNvsCBBXHZIAsTnDzyp-m3x0azcumsfgAv2y6w-Gpbckew3uKwcfb8Hic55HnVsFoE","Dq":"Gc68rsTLYPQ-hbS1N5LdJ0KlPhoMxahyrBgldz5PkzTPhIULYn3wyFA37WhrIbQ7H3Nn6X1IWBbHqFghk34ENRoNeo6Yq5MFV4WD6Wrldc90y1RKr5LF8CYZJ1TBM6qfFj-_UKPugtsFPJ8t7xWJjO7_oU0RYrbrhoInz3LoWFU","E":"AQAB","N":"rhhtw80Tt9wid3mTYTUNDnlLu24d7xMrvYtkqGGV0oqv-EoOgwnB4xByGQzg5mr-Ek-NjR91viHnFFwpS36thoK0A54tSylWLpMLjr2tIY56CX56-SIC-j4waOMQwJmMn1_7YcZ3enbdc1NYcnzNwxnc-gkmqqJX_QCUPCUMGMQQsl6mMyhbiLc7vOiarhZgj1vP4DjFiBmg1jm1SdL5HwRmDe3ogYuUJvM2INuWOilr69zUSpRv7RoPiUAFPSoE98qBajapOqCa5RV4RYKur-1Dwc11TrBWPv9cuG09aOcZah7oJn_B4Ab4lxUzH_f95ytdS4IiA4YFeCY3GPpLQw","P":"4dOI1fyPZr055ErouAIA1XVOjrd9ivX9NIq2jtn8B_QACzIyZX-u3M3CqjExAFB2bgbPqWFTYykUjcBKVGjDqtdB_JMKPQqJBWU2WblqHUUgHP8RNOjh9WBUFTcMDXBySkY_zicTg7Jpga43waBs6IQztYwUcxUhPccaT5BiXfE","Q":"xVtsAEh5F5ZbtFeNLordeNrLggo-ATs3KMT14pmBRSJvCvMm_58TIByvGK8u9j4oYIBPPxCaiYC9PZbKKPjDGGIOW0o84i3KbS01cDjXkyzTVeIwRL-VBv21e6p2qappDgE92IwDTzSi-BELHsCDB_ZWowAj1ufe8eQcAf4zmHM","Qi":"B7ivHCwsNUkqS4lpjoKZiDrnOcHak5i1l-sUg-JdTsm2-06KhrLCgDHdvMwnP2z8Bg8UGrHCMI7dOaMiHVuQH68tAZ95w38apMIbiq8Ocd32oBETExJDwBUZE83bDgYoq_qi2sKvHVEcW2x9dqio7eLWY4XC_AW5lHvKReUlU4c"}}
`

	cipherhex := "87a4d6c0ecc309d032743d73670dffb9640ce302f6fcb35cc840ef62351c6067bd7dc3fbbb0f31e90878e753363eb6e6687b12dfecd77456e40164f0f28994b24f5956200f7d741484aa9e867056a33399537b78e43c6abd7d672bb1c9b5b8ebcef281b5c22b703fae1956d218a8c8bcc4560d9744896368c9cdc85ca8da502a54d1cc007b3d9619b42b65ccb9cfa65ed18211f6a83405389fb61041dd51cb591d7d4d669f9244875d5332de759f230e0ba61470b91bf364ec7583fd003d54cb63a3845adb133cbc9e9966246349133ea275567c41efade258b1fd06d95ea9aad06bba3f04bdc761a66ffd7a3ad5e10528a073cc5dbdf010067677588a68c111"
	ciphertext, _ := hex.DecodeString(cipherhex)

	private := PrivateKey{}
	err := json.Unmarshal([]byte(privatejson), &private)
	require.Nil(t, err)

	decrypter, err := NewDecrypter(private)
	require.Nil(t, err)
	require.NotNil(t, decrypter)

	cleartext, err := decrypter.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}
