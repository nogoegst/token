// token.go - simple secure expiring tokens.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of token, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package token

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize                  = chacha20poly1305.KeySize
	chacha20poly1305Overhead = 16
	TokenPlaintextSize       = 8
	TokenSize                = chacha20poly1305.NonceSize + TokenPlaintextSize + chacha20poly1305Overhead
)

var (
	TokenExpired     = errors.New("token expired")
	InvalidTokenSize = errors.New("invalid token size")
)

type Token struct {
	ExpirationTime int64
}

func NewTokenWithTime(exp time.Time) *Token {
	return &Token{
		ExpirationTime: exp.Unix(),
	}
}

func NewTokenWithDuration(d time.Duration) *Token {
	return NewTokenWithTime(time.Now().Add(d))
}

func New(d time.Duration, key []byte) ([]byte, error) {
	t := NewTokenWithDuration(d)
	return t.Seal(key)
}

func Verify(t, key []byte) error {
	tt, err := Open(t, key)
	if err != nil {
		return err
	}
	if !tt.IsValid() {
		return TokenExpired
	}
	return nil
}

func (t *Token) IsValid() bool {
	return time.Now().Before(time.Unix(t.ExpirationTime, 0))
}

func (t *Token) Seal(key []byte) ([]byte, error) {
	mt, err := asn1.Marshal(*t)
	if err != nil {
		return nil, err
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ct := c.Seal(nonce, nonce, mt, nil)
	return ct, nil
}

func Open(ct, key []byte) (*Token, error) {
	t := &Token{}
	if len(ct) != TokenSize {
		return nil, InvalidTokenSize
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, 0, TokenPlaintextSize)
	mt, err := c.Open(dst, ct[:chacha20poly1305.NonceSize], ct[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, err
	}
	_, err = asn1.Unmarshal(mt, t)
	if err != nil {
		return nil, err
	}
	return t, nil
}
