// token_test.go
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to token, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package symmetrictoken

import (
	"crypto/rand"
	"io"
	"log"
	"reflect"
	"testing"
	"time"
)

func TestCurrentToken(t *testing.T) {
	key, _, err := Locker.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := NewWithDuration(100*time.Millisecond, key, payload)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%x", tok)
	time.Sleep(50 * time.Millisecond)
	tt, err := Verify(tok, key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", payload, tt.Payload)
	}

	time.Sleep(150 * time.Millisecond)
	tt, err = Verify(tok, key)
	if err == nil {
		log.Printf("%v", tt.ExpirationTime())
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, tt.Payload) {
		t.Fatalf("wrong additional data: want %x, got %x", payload, tt.Payload)
	}
}
