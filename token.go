// token.go - simple secure expiring tokens.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package token

import (
	"encoding/asn1"
	"errors"
	"time"
)

var (
	ErrExpired = errors.New("token expired")
)

type Token struct {
	ExpirationTimestamp int64 // in milliseconds
	Payload             []byte
}

func (t *Token) ExpirationTime() time.Time {
	msec := t.ExpirationTimestamp % 1e3
	sec := (t.ExpirationTimestamp - msec) / 1e3
	return time.Unix(sec, msec*1e6)
}

func NewWithTime(exp time.Time, payload ...[]byte) (*Token, error) {
	if len(payload) > 1 {
		return nil, errors.New("additional data must be specified as most once")
	}
	t := &Token{
		ExpirationTimestamp: exp.UnixNano() / 1e6,
	}
	if len(payload) == 1 {
		t.Payload = payload[0]
	}
	return t, nil
}

func NewWithDuration(d time.Duration, payload ...[]byte) (*Token, error) {
	return NewWithTime(time.Now().Add(d), payload...)
}

func (t *Token) Verify() error {
	if !time.Now().Before(t.ExpirationTime()) {
		return ErrExpired
	}
	return nil
}

func (t *Token) Marshal() ([]byte, error) {
	return asn1.Marshal(*t)
}

func Unmarshal(mt []byte) (*Token, error) {
	t := &Token{}
	_, err := asn1.Unmarshal(mt, t)
	if err != nil {
		return nil, err
	}
	return t, nil
}
