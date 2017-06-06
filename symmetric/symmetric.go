// symmetric.go - simple secure expiring tokens with symmetric keys.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package symmetrictoken

import (
	"errors"
	"time"

	"github.com/nogoegst/locker"
	"github.com/nogoegst/token"
)

var (
	ErrInvalidSize = errors.New("invalid ciphertext size")
	ErrDecrypt     = errors.New("unable to decrypt token")
	ErrUnmarshal   = errors.New("unable to unmarshal token")
	Locker         = locker.Symmetric
	KeySize        = locker.KeySize
)

func seal(t *token.Token, key []byte) ([]byte, error) {
	pt, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	ct, err := Locker.Seal(pt, key)
	return ct, err
}

func NewWithTime(d time.Time, key []byte, adata ...[]byte) ([]byte, error) {
	t, err := token.NewWithTime(d, adata...)
	if err != nil {
		return nil, err
	}
	return seal(t, key)
}

func NewWithDuration(d time.Duration, key []byte, adata ...[]byte) ([]byte, error) {
	t, err := token.NewWithDuration(d, adata...)
	if err != nil {
		return nil, err
	}
	return seal(t, key)
}

func Verify(t, key []byte) (*token.Token, error) {
	tt, err := Locker.Open(t, key)
	if err != nil {
		return nil, ErrDecrypt
	}
	tok, err := token.Unmarshal(tt)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if err := tok.Verify(); err != nil {
		return tok, err
	}
	return tok, nil
}
