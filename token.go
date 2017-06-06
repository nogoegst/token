// token.go - simple secure expiring tokens.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package token

import (
	"errors"
	"time"

	"github.com/nogoegst/locker"
	"github.com/nogoegst/token/plain"
)

var (
	ErrDecrypt   = errors.New("unable to decrypt token")
	ErrUnmarshal = errors.New("unable to unmarshal token")
	Locker       = locker.SealOpener(locker.Symmetric)
)

func NewWithTime(d time.Time, key []byte, payload ...[]byte) ([]byte, error) {
	t, err := plaintoken.NewWithTime(d, payload...)
	if err != nil {
		return nil, err
	}
	return Seal(t, key)
}

func NewWithDuration(d time.Duration, key []byte, payload ...[]byte) ([]byte, error) {
	t, err := plaintoken.NewWithDuration(d, payload...)
	if err != nil {
		return nil, err
	}
	return Seal(t, key)
}

func Seal(t *plaintoken.Token, key []byte) ([]byte, error) {
	pt, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	ct, err := Locker.Seal(pt, key)
	return ct, err
}

func Verify(t, key []byte) (*plaintoken.Token, error) {
	tt, err := Locker.Open(t, key)
	if err != nil {
		return nil, ErrDecrypt
	}
	tok, err := plaintoken.Unmarshal(tt)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if err := tok.Verify(); err != nil {
		return tok, err
	}
	return tok, nil
}
