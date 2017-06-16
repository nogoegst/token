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
	ErrDecode = errors.New("unable to decode token")
)

func NewWithTime(l locker.Sealer, key []byte, d time.Time, payload, adata []byte) ([]byte, error) {
	t, err := plaintoken.NewWithTime(d, payload)
	if err != nil {
		return nil, err
	}
	return Seal(l, key, t, adata)
}

func NewWithDuration(l locker.Sealer, key []byte, d time.Duration, payload, adata []byte) ([]byte, error) {
	t, err := plaintoken.NewWithDuration(d, payload)
	if err != nil {
		return nil, err
	}
	return Seal(l, key, t, adata)
}

func Seal(sr locker.Sealer, key []byte, t *plaintoken.Token, adata []byte) ([]byte, error) {
	pt, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	ct, err := sr.Seal(key, pt, adata)
	return ct, err
}

func Verify(or locker.Opener, key, t, adata []byte) (*plaintoken.Token, error) {
	tt, err := or.Open(key, t, adata)
	if err != nil {
		return nil, ErrDecode
	}
	tok, err := plaintoken.Unmarshal(tt)
	if err != nil {
		return nil, ErrDecode
	}
	if err := tok.Verify(); err != nil {
		return tok, err
	}
	return tok, nil
}
