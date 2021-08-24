package nkeys

import "encoding/hex"

type HexEncoding struct{}

func (_ HexEncoding) Decode(d, s []byte) (int, error) {
	return hex.Decode(d, s)
}
func (_ HexEncoding) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (_ *HexEncoding) DecodedLen(x int) int {
	return hex.DecodedLen(x)
}
func (_ HexEncoding) Encode(d, s []byte) int {
	return hex.Encode(d, s)
}
func (_ HexEncoding) EncodeToString(s []byte) string {
	return hex.EncodeToString(s)
}

func (_ HexEncoding) EncodedLen(x int) int {
	return hex.EncodedLen(x)
}
