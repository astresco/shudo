package securejson

import (
	"bytes"
	"testing"

	"shudo.local/shudo/internal/model"
)

func TestRequestHashMatchesCanonicalFixture(t *testing.T) {
	username, group := "alice", "users"
	device, inode, size, owner, mode := uint64(1), uint64(2), uint64(3), uint32(0), uint32(33261)
	mtime, ctime := "1", "2"
	request := model.ExecutionRequest{
		Version: 1, RequestID: "018f0000-0000-7000-8000-000000000001",
		Requester:                model.Requester{UID: 1000, GID: 100, Username: &username, GroupName: &group},
		Execution:                model.Execution{Executable: "/usr/bin/id", Argv: []string{}, Cwd: "/home/alice", Env: map[string]string{"Z": "last", "A": "first"}},
		ExecutableMetadata:       model.FileMetadata{Path: "/usr/bin/id", Device: &device, Inode: &inode, Size: &size, OwnerUID: &owner, Mode: &mode, MtimeNS: &mtime, CtimeNS: &ctime, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		WorkingDirectoryMetadata: model.WorkingDirectoryMetadata{Path: "/home/alice", Device: 1, Inode: 4, OwnerUID: 1000, Mode: 16877, MtimeNS: "3", CtimeNS: "4"},
		Risk:                     model.RiskMetadata{EnvironmentOverrides: true, Warnings: []string{"Environment overrides change execution context"}},
		PolicyResult:             "require-approval", Reason: "build needs identity", CreatedAt: "2026-08-26T03:00:00Z", ExpiresAt: "2026-08-26T03:05:00Z", Nonce: "bm9uY2U",
	}
	hash, err := Hash(request)
	if err != nil {
		t.Fatal(err)
	}
	if expected := "8b76a47dda0ad64d8592ecac5e6b7d77b1a0c719ed14bc3bfd621aa9260e8563"; hash != expected {
		t.Fatalf("canonical request hash mismatch: got %s", hash)
	}
}

func TestDecodeStrictRejectsUnknownFields(t *testing.T) {
	var destination struct {
		Version int `json:"version"`
	}
	if err := DecodeStrict([]byte(`{"version":1,"execute":"forbidden"}`), &destination); err == nil {
		t.Fatal("unknown network field was accepted")
	}
}

func TestCanonicalJSONAndStrictDecodeEdges(t *testing.T) {
	raw, err := MarshalCanonical(map[string]any{"z": 1, "a": 2})
	if err != nil || string(raw) != `{"a":2,"z":1}` {
		t.Fatalf("unexpected canonical JSON: %s %v", raw, err)
	}
	if _, err := MarshalCanonical(make(chan int)); err == nil {
		t.Fatal("unsupported value was canonicalized")
	}
	if _, err := Hash(make(chan int)); err == nil {
		t.Fatal("unsupported value was hashed")
	}

	var destination struct {
		Version int `json:"version"`
	}
	if err := DecodeStrict([]byte(`{"version":1}`), &destination); err != nil || destination.Version != 1 {
		t.Fatalf("valid JSON rejected: %#v %v", destination, err)
	}
	for _, input := range [][]byte{
		[]byte(`{"version":`),
		[]byte(`{"version":1} {}`),
		bytes.Repeat([]byte("x"), 4),
	} {
		if err := DecodeStrict(input, &destination); err == nil {
			t.Fatalf("invalid JSON accepted: %q", input)
		}
	}
}
