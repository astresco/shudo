package cryptoutil

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestUUIDAndNonceAreUnique(t *testing.T) {
	first, _ := UUID()
	second, _ := UUID()
	if first == second || len(first) != 36 {
		t.Fatal("invalid UUID generation")
	}
	a, _ := Nonce(24)
	b, _ := Nonce(24)
	if a == b || a == "" {
		t.Fatal("invalid nonce generation")
	}
}

func TestEqual(t *testing.T) {
	if !Equal("request-hash", "request-hash") || Equal("request-hash", "different") || Equal("a", "aa") {
		t.Fatal("constant-time equality returned an invalid result")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestEntropyFailuresAreReturned(t *testing.T) {
	original := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = original })
	if _, err := Nonce(24); err == nil {
		t.Fatal("nonce ignored entropy failure")
	}
	if _, err := UUID(); err == nil {
		t.Fatal("UUID ignored entropy failure")
	}
}

func TestUUIDVersionAndNonceEncoding(t *testing.T) {
	id, err := UUID()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 || parts[2][0] != '4' || !strings.Contains("89ab", parts[3][:1]) {
		t.Fatalf("not an RFC 4122 version 4 UUID: %s", id)
	}
	nonce, err := Nonce(0)
	if err != nil || nonce != "" {
		t.Fatalf("zero-length nonce mismatch: %q %v", nonce, err)
	}
}
