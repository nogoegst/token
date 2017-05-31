// token.go - simple secure expiring tokens.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package asymmetrictoken

import (
	"errors"
	"time"

	"github.com/nogoegst/locker"
	"github.com/nogoegst/token"
)

var (
	ErrInvalidSize = errors.New("invalid ciphertext size")
	Locker         = locker.NewAsymmetric()
	KeySize        = locker.KeySize
)

func NewWithTime(d time.Time, key []byte, adata ...[]byte) ([]byte, error) {
	t, err := token.NewWithTime(d, adata...)
	if err != nil {
		return nil, err
	}
	return Seal(t, key)
}

func NewWithDuration(d time.Duration, key []byte, adata ...[]byte) ([]byte, error) {
	t, err := token.NewWithDuration(d, adata...)
	if err != nil {
		return nil, err
	}
	return Seal(t, key)
}

func Seal(t *token.Token, key []byte) ([]byte, error) {
	pt, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	ct, err := Locker.Seal(pt, key)
	return ct, err
}

func Verify(t, key []byte) (*token.Token, error) {
	tt, err := Locker.Open(t, key)
	if err != nil {
		return nil, err
	}
	tok, err := token.Unmarshal(tt)
	if err != nil {
		return nil, err
	}
	if err := tok.Verify(); err != nil {
		return tok, err
	}
	return tok, nil
}
