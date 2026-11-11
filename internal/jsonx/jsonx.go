package jsonx

import (
	"errors"

	"signer/internal/contract"
)

var (
	ErrFormat         = errors.New("invalid JSON format")
	ErrNotImplemented = contract.ErrNotImplemented
)

func Decode(data []byte) (any, error) {
	return nil, ErrNotImplemented
}
