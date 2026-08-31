//go:build linux

package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"
	"shudo.local/shudo/internal/localcreds"
	"shudo.local/shudo/internal/model"
	"shudo.local/shudo/internal/state"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func peerContext(uid, gid uint32) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: localcreds.AuthInfo{UID: uid, GID: gid, PID: 42}})
}

func TestRootAuthorityComesOnlyFromPeerCredentials(t *testing.T) {
	if _, err := rootRequester(peerContext(1000, 1000)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-root peer was not denied: %v", err)
	}
	actor, err := rootRequester(peerContext(0, 0))
	if err != nil || actor.UID != 0 {
		t.Fatalf("root peer was not authenticated: %#v %v", actor, err)
	}
	if _, err := rootRequester(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing peer credentials were accepted: %v", err)
	}
}

func TestSubmitValidationBoundsUntrustedFields(t *testing.T) {
	valid := &shudov1.SubmitRequest{Executable: "/usr/bin/id", Cwd: "/", Reason: "test", TimeoutMs: 1000}
	if err := validateSubmit(valid); err != nil {
		t.Fatal(err)
	}
	invalid := []*shudov1.SubmitRequest{
		{Executable: "/usr/bin/id\x00x", Cwd: "/", Reason: "test", TimeoutMs: 1000},
		{Executable: "/usr/bin/id", Cwd: "relative", Reason: "test", TimeoutMs: 1000},
		{Executable: "/usr/bin/id", Cwd: "/", Reason: " ", TimeoutMs: 1000},
		{Executable: "/usr/bin/id", Cwd: "/", Reason: "test", TimeoutMs: 999},
	}
	for index, input := range invalid {
		if validateSubmit(input) == nil {
			t.Fatalf("invalid input %d was accepted", index)
		}
	}
}

func TestCommandDisplayEscapesControlCharacters(t *testing.T) {
	got := command("/usr/bin/printf", []string{"safe", "\x1b[2Jspoof", "two words"})
	if got != `/usr/bin/printf safe "\x1b[2Jspoof" "two words"` {
		t.Fatalf("unsafe command rendering: %q", got)
	}
}

func TestRequestReviewRequiresRoot(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, record := range []struct {
		id  string
		uid uint32
	}{{"request-user-a", 1000}, {"request-user-b", 1001}} {
		request := model.ExecutionRequest{
			Version: 1, RequestID: record.id, Requester: model.Requester{UID: record.uid},
			Execution: model.Execution{Executable: "/usr/bin/id", Cwd: "/"}, Reason: "test",
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		}
		if err := store.Create(request, "hash-"+record.id); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(record.id, model.Waiting, model.Created); err != nil {
			t.Fatal(err)
		}
	}
	service := &Service{Store: store}
	if _, err := service.ListRequests(peerContext(1000, 1000), &shudov1.ListRequestsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-root listing was not denied: %v", err)
	}
	if _, err := service.InspectRequest(peerContext(1000, 1000), &shudov1.InspectRequestRequest{RequestId: "request-user-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-root inspection was not denied: %v", err)
	}
	rootView, err := service.ListRequests(peerContext(0, 0), &shudov1.ListRequestsRequest{})
	if err != nil || len(rootView.Requests) != 2 {
		t.Fatalf("root did not see all requests: %#v %v", rootView, err)
	}
	rootRecord, err := service.InspectRequest(peerContext(0, 0), &shudov1.InspectRequestRequest{RequestId: "request-user-a"})
	if err != nil || rootRecord.RequestId != "request-user-a" {
		t.Fatalf("root could not inspect request: %#v %v", rootRecord, err)
	}
}
