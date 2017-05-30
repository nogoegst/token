// token.go - simple secure expiring tokens.
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
)

func TestCurrentToken(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatal(err)
	}
	adata := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, adata)
	if err != nil {
		t.Fatal(err)
	}

	tokn := NewWithDuration(100*time.Millisecond, adata)
	tok, err := tokn.Seal(key)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%x", tok)
	time.Sleep(50 * time.Millisecond)
	tt, err := Verify(tok, key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(adata, tt.AdditionalData) {
		t.Fatalf("wrong additional data: want %x, got %x", adata, tt.AdditionalData)
	}

	time.Sleep(150 * time.Millisecond)
	tt, err = Verify(tok, key)
	if err == nil {
		log.Printf("%v", tt.ExpirationTime())
		t.Fatal(err)
	}
	if !reflect.DeepEqual(adata, tt.AdditionalData) {
		t.Fatalf("wrong additional data: want %x, got %x", adata, tt.AdditionalData)
	}
}
