// token_test.go
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package asymmetrictoken

import (
	"crypto/rand"
	"io"
	"log"
	"reflect"
	"testing"
	"time"
)

func TestCurrentToken(t *testing.T) {
	spk, ssk, err := Locker.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, sk, err := Locker.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourcekey := append(ssk, pk...)
	key := append(sk, spk...)

	adata := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, adata)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := NewWithDuration(100*time.Millisecond, sourcekey, adata)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%x", tok)
	time.Sleep(50 * time.Millisecond)
	tt, err := Verify(tok, key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(adata, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", adata, tt.Payload)
	}

	bpk, bsk, err := Locker.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badkey := append(bsk, bpk...)
	_, err = Verify(tok, badkey)
	if err == nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond)
	tt, err = Verify(tok, key)
	if err == nil {
		log.Printf("%v", tt.ExpirationTime())
		t.Fatal(err)
	}
	if !reflect.DeepEqual(adata, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", adata, tt.Payload)
	}
}
