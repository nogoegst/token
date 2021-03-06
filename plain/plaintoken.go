// plaintoken.go - simple expiring tokens.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package plaintoken

import (
	"encoding/binary"
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
		return nil, errors.New("payload must be specified as most once")
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
	ret := make([]byte, 8+len(t.Payload))
	binary.BigEndian.PutUint64(ret[:8], uint64(t.ExpirationTimestamp))
	copy(ret[8:], t.Payload)
	return ret, nil
}

func Unmarshal(mt []byte) (*Token, error) {
	if len(mt) < 8 {
		return nil, errors.New("invalid data length")
	}
	t := &Token{}
	t.ExpirationTimestamp = int64(binary.BigEndian.Uint64(mt[:8]))
	t.Payload = mt[8:]
	return t, nil
}
