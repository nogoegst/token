// token_test.go
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package token

import (
	"crypto/rand"
	"io"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/nogoegst/locker"
)

func TestSymmetricToken(t *testing.T) {
	key, _, err := locker.Symmetric.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := NewWithDuration(locker.Symmetric, key, 100*time.Millisecond, payload)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%x", tok)
	time.Sleep(50 * time.Millisecond)
	tt, err := Verify(locker.Symmetric, key, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", payload, tt.Payload)
	}

	time.Sleep(150 * time.Millisecond)
	tt, err = Verify(locker.Symmetric, key, tok)
	if err == nil {
		log.Printf("%v", tt.ExpirationTime())
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", payload, tt.Payload)
	}
}

func TestScrambleSignedToken(t *testing.T) {
	pk, sk, err := locker.ScrambleSigned.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := NewWithDuration(locker.ScrambleSigned, sk, 100*time.Millisecond, payload)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%x", tok)
	time.Sleep(50 * time.Millisecond)
	tt, err := Verify(locker.ScrambleSigned, pk, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", payload, tt.Payload)
	}

	badpk, _, err := locker.ScrambleSigned.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(locker.ScrambleSigned, badpk, tok)
	if err == nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond)
	tt, err = Verify(locker.ScrambleSigned, pk, tok)
	if err == nil {
		log.Printf("%v", tt.ExpirationTime())
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", payload, tt.Payload)
	}
}
