// token.go - simple secure expiring tokens.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
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
	Overhead                 = chacha20poly1305.NonceSize + chacha20poly1305Overhead
)

var (
	ErrExpired     = errors.New("token expired")
	ErrInvalidSize = errors.New("invalid token size")
)

type Token struct {
	ExpirationTimestamp int64 // in milliseconds
	AdditionalData      []byte
}

func (t *Token) PlaintextSize() int {
	return 8
}

func (t *Token) CiphertextSize() int {
	return t.PlaintextSize() + Overhead
}

func (t *Token) ExpirationTime() time.Time {
	msec := t.ExpirationTimestamp % 1e3
	sec := (t.ExpirationTimestamp - msec) / 1e3
	return time.Unix(sec, msec*1e6)
}

func NewWithTime(exp time.Time, adata ...[]byte) *Token {
	if len(adata) > 1 {
		panic("additional data must be specified as most once")
	}
	t := &Token{
		ExpirationTimestamp: exp.UnixNano() / 1e6,
	}
	if len(adata) == 1 {
		t.AdditionalData = adata[0]
	}
	return t
}

func NewWithDuration(d time.Duration, adata ...[]byte) *Token {
	return NewWithTime(time.Now().Add(d), adata...)
}

func Verify(t, key []byte) (*Token, error) {
	tt, err := Open(t, key)
	if err != nil {
		return nil, err
	}
	if !tt.IsValid() {
		return tt, ErrExpired
	}
	return tt, nil
}

func (t *Token) IsValid() bool {
	return time.Now().Before(t.ExpirationTime())
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
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < chacha20poly1305.NonceSize {
		return nil, ErrInvalidSize
	}
	mt, err := c.Open(nil, ct[:chacha20poly1305.NonceSize], ct[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, err
	}
	v := &Token{}
	_, err = asn1.Unmarshal(mt, v)
	if err != nil {
		return nil, err
	}
	return v, nil
}
