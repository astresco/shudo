//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"
	"shudo.local/shudo/internal/config"
	"shudo.local/shudo/internal/integrity"
	"shudo.local/shudo/internal/localcreds"
	"shudo.local/shudo/internal/model"
	"shudo.local/shudo/internal/securejson"
	"shudo.local/shudo/internal/state"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__exec-fds" {
		if len(os.Args) < 6 {
			os.Exit(127)
		}
		var interpreterArgument *string
		if os.Args[4] == "1" {
			interpreterArgument = &os.Args[5]
		}
		interpreterFD := -1
		if os.Args[3] != "" {
			interpreterFD = integrity.InterpreterFD
		}
		if err := integrity.ExecPinned(integrity.ExecutableFD, integrity.DirectoryFD, interpreterFD, os.Args[2], os.Args[6:], os.Environ(), os.Args[3], interpreterArgument); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(127)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "__exec-fd" {
		if len(os.Args) < 3 {
			os.Exit(127)
		}
		if err := integrity.ExecVerified(3, os.Args[2:], os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(127)
		}
	}
	os.Exit(m.Run())
}

func namedPeerContext(uid, gid uint32, username, group string) context.Context {
	auth := localcreds.AuthInfo{UID: uid, GID: gid, PID: 42, Username: username, GroupName: group}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: auth})
}

func testService(t *testing.T, defaultAction string) (*Service, *state.Store, string) {
	t.Helper()
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "policy.yaml")
	writeTestPolicy(t, policyPath, defaultAction)
	store, err := state.Open(filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := New(config.Daemon{
		PolicyPath: policyPath, MaxPendingPerUID: 8,
		MaxPendingTotal: 256, MaxExecutionSeconds: 5,
		Output: config.Output{LiveBytes: 1024, PersistedBytes: 1024 * 1024},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	return service, store, policyPath
}

func writeTestPolicy(t *testing.T, path, defaultAction string) {
	t.Helper()
	body := fmt.Sprintf("version: 1\ndefaults:\n  action: %s\nrules: []\n", defaultAction)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func validSubmit(executable string, argv ...string) *shudov1.SubmitRequest {
	return &shudov1.SubmitRequest{
		Executable: executable, Argv: argv, Cwd: "/", Reason: "unit test request", TimeoutMs: 10_000,
	}
}

func approvalRequest(t *testing.T, service *Service, requestID string) *shudov1.DecisionRequest {
	t.Helper()
	item, err := service.Store.Get(requestID)
	if err != nil || item == nil {
		t.Fatalf("approval target missing: %#v %v", item, err)
	}
	return &shudov1.DecisionRequest{RequestId: requestID, RequestHash: item.RequestHash}
}

func persistApproved(t *testing.T, store *state.Store, request model.ExecutionRequest, hash string) {
	t.Helper()
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{Version: 1, ApprovalID: "approval-" + request.RequestID, RequestID: request.RequestID, RequestHash: hash, Decision: "approve", ApprovedBy: model.ApprovedBy{Subject: "uid:0"}, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
}

func waitForStatus(t *testing.T, store *state.Store, requestID string, terminal bool) *state.StoredRequest {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		item, err := store.Get(requestID)
		if err != nil {
			t.Fatal(err)
		}
		if item != nil && ((!terminal && item.Status != model.Created) || (terminal && model.Terminal(item.Status))) {
			return item
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("request %s did not reach expected state", requestID)
	return nil
}

func TestRequesterAndSubmitValidationEdges(t *testing.T) {
	if _, err := requester(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing peer accepted: %v", err)
	}
	badPeer := peer.NewContext(context.Background(), &peer.Peer{})
	if _, err := requester(badPeer); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid peer accepted: %v", err)
	}
	actor, err := requester(namedPeerContext(1000, 100, "alice", "users"))
	if err != nil || actor.Username == nil || *actor.Username != "alice" || actor.GroupName == nil || *actor.GroupName != "users" {
		t.Fatalf("peer names lost: %#v %v", actor, err)
	}

	tooManyArguments := make([]string, 4097)
	tooManyEnvironment := make(map[string]string, 257)
	for index := 0; index < 257; index++ {
		tooManyEnvironment[fmt.Sprintf("K%d", index)] = "v"
	}
	cases := []*shudov1.SubmitRequest{
		nil,
		{Executable: strings.Repeat("x", 4097), Cwd: "/", Reason: "x", TimeoutMs: 1000},
		{Executable: "/bin/true", Cwd: strings.Repeat("x", 4097), Reason: "x", TimeoutMs: 1000},
		{Executable: "/bin/true", Cwd: "/", Reason: "x\x00", TimeoutMs: 1000},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 999},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Argv: tooManyArguments},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Env: tooManyEnvironment},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Argv: []string{strings.Repeat("x", 131073)}},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Argv: []string{"x\x00"}},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Env: map[string]string{strings.Repeat("K", 257): "x"}},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Env: map[string]string{"K": strings.Repeat("x", 65537)}},
		{Executable: "/bin/true", Cwd: "/", Reason: "x", TimeoutMs: 1000, Argv: []string{strings.Repeat("x", 131072), strings.Repeat("y", 131072), strings.Repeat("z", 131072), "x"}},
	}
	for index, input := range cases {
		if err := validateSubmit(input); err == nil {
			t.Fatalf("invalid submit %d accepted", index)
		}
	}
	if err := validateSubmit(validSubmit("/bin/true")); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitPolicyOutcomesAndAdmission(t *testing.T) {
	service, store, policyPath := testService(t, "require-approval")
	ctx := namedPeerContext(1000, 100, "alice", "users")
	response, err := service.Submit(ctx, validSubmit("/usr/bin/printf", "hello"))
	if err != nil || response.Status != model.Waiting || response.RequestId == "" || response.RequestHash == "" || !strings.Contains(response.Command, "printf hello") {
		t.Fatalf("valid submit failed: %#v %v", response, err)
	}
	item, err := store.Get(response.RequestId)
	if err != nil || item.Request.Requester.Username == nil || *item.Request.Requester.Username != "alice" {
		t.Fatalf("request identity not persisted: %#v %v", item, err)
	}

	writeTestPolicy(t, policyPath, "deny")
	denied, err := service.Submit(ctx, validSubmit("/usr/bin/true"))
	if err != nil || denied.Status != model.PolicyRejected {
		t.Fatalf("policy deny failed: %#v %v", denied, err)
	}

	writeTestPolicy(t, policyPath, "allow")
	if _, err := service.Submit(ctx, validSubmit("/usr/bin/true")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("obsolete automatic allow policy did not fail closed: %v", err)
	}
	writeTestPolicy(t, policyPath, "require-approval")
	withEnvironment := validSubmit("/usr/bin/true")
	withEnvironment.Env = map[string]string{"TERM": "xterm"}
	if _, err := service.Submit(ctx, withEnvironment); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("environment override was accepted: %v", err)
	}

	service.Config.MaxPendingPerUID = 1
	if _, err := service.Submit(ctx, validSubmit("/usr/bin/true")); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("per-user quota not enforced: %v", err)
	}
}

func TestSubmitRejectsInvalidInputsAndDependencies(t *testing.T) {
	service, _, policyPath := testService(t, "require-approval")
	ctx := peerContext(1000, 1000)
	tests := []struct {
		name  string
		input *shudov1.SubmitRequest
		code  codes.Code
	}{
		{"invalid body", &shudov1.SubmitRequest{}, codes.InvalidArgument},
		{"relative cwd", &shudov1.SubmitRequest{Executable: "/bin/true", Cwd: "relative", Reason: "x", TimeoutMs: 1000}, codes.InvalidArgument},
		{"environment", func() *shudov1.SubmitRequest {
			value := validSubmit("/bin/true")
			value.Env = map[string]string{"LD_PRELOAD": "x"}
			return value
		}(), codes.InvalidArgument},
		{"missing executable", validSubmit("/definitely/missing"), codes.InvalidArgument},
		{"bad directory", func() *shudov1.SubmitRequest {
			value := validSubmit("/bin/true")
			value.Cwd = "/definitely/missing"
			return value
		}(), codes.InvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.Submit(ctx, test.input); status.Code(err) != test.code {
				t.Fatalf("got %v", err)
			}
		})
	}
	directory := t.TempDir()
	nonExecutable := filepath.Join(directory, "plain")
	if err := os.WriteFile(nonExecutable, []byte("plain"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Submit(ctx, validSubmit(nonExecutable)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("non-executable file accepted: %v", err)
	}
	badScript := filepath.Join(directory, "bad-script")
	if err := os.WriteFile(badScript, []byte("#!relative\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Submit(ctx, validSubmit(badScript)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid interpreter accepted: %v", err)
	}
	if _, err := service.Submit(context.Background(), validSubmit("/bin/true")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated submit accepted: %v", err)
	}
	if err := os.WriteFile(policyPath, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Submit(ctx, validSubmit("/bin/true")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("invalid policy accepted: %v", err)
	}
}

func TestSubmitEnforcesExecutableAndStorageLimits(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	directory := t.TempDir()
	executable := filepath.Join(directory, "large-tool")
	if err := os.WriteFile(executable, make([]byte, 4096), 0755); err != nil {
		t.Fatal(err)
	}
	service.Config.MaxExecutableBytes = 1024
	if _, err := service.Submit(peerContext(1000, 1000), validSubmit(executable)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized executable accepted: %v", err)
	}
	service.Config.MaxExecutableBytes = 1024 * 1024
	store.SetMaxBytes(1)
	if _, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/true")); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("state storage limit was not surfaced: %v", err)
	}
}

func TestDecisionLifecycleAndIntegrity(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	request, err := service.Submit(peerContext(1000, 1000), validSubmit("/usr/bin/printf", "approved-output"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(peerContext(1000, 1000), &shudov1.DecisionRequest{RequestId: request.RequestId}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-root approval accepted: %v", err)
	}
	if _, err := service.Approve(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: request.RequestId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("hashless approval accepted: %v", err)
	}
	response, err := service.Approve(namedPeerContext(0, 0, "root", "root"), approvalRequest(t, service, request.RequestId))
	if err != nil || response.Status != model.Approved || response.DecidedBy != "root" {
		t.Fatalf("approval failed: %#v %v", response, err)
	}
	if item := waitForStatus(t, store, request.RequestId, true); item.Status != model.Succeeded {
		t.Fatalf("approved command failed: %#v", item)
	}
	repeatedApproval, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, request.RequestId))
	if err != nil || repeatedApproval.ApprovalId != response.ApprovalId || repeatedApproval.Status != model.Approved {
		t.Fatalf("approval retry was not idempotent: %#v %v", repeatedApproval, err)
	}
	chunks, err := store.Output(request.RequestId)
	if err != nil || len(chunks) == 0 || string(chunks[0].Data) != "approved-output" {
		t.Fatalf("approved output missing: %#v %v", chunks, err)
	}

	denied, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := service.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: denied.RequestId})
	if err != nil || decision.Status != model.Denied || decision.DecidedBy != "uid:0" {
		t.Fatalf("denial failed: %#v %v", decision, err)
	}
	repeatedDenial, err := service.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: denied.RequestId})
	if err != nil || repeatedDenial.ApprovalId != decision.ApprovalId || repeatedDenial.Status != model.Denied {
		t.Fatalf("denial retry was not idempotent: %#v %v", repeatedDenial, err)
	}
	if _, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, denied.RequestId)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("conflicting decision accepted: %v", err)
	}
	if _, err := service.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing decision target accepted: %v", err)
	}
	if _, err := service.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: "missing", Reason: strings.Repeat("x", 4097)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized decision reason accepted: %v", err)
	}

	tampered := testExecutionRequest(t, "tampered-decision", "/bin/true", nil, time.Now().Add(time.Minute))
	if err := store.Create(tampered, "wrong-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(tampered.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, tampered.RequestID)); status.Code(err) != codes.DataLoss {
		t.Fatalf("tampered request approved: %v", err)
	}
}

func TestCancelledDecisionContextDoesNotCommit(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	submitted, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}
	request := approvalRequest(t, service, submitted.RequestId)
	ctx, cancel := context.WithCancel(peerContext(0, 0))
	cancel()
	if _, err := service.Approve(ctx, request); status.Code(err) != codes.Canceled {
		t.Fatalf("cancelled decision returned %v", err)
	}
	item, err := store.Get(submitted.RequestId)
	if err != nil || item.Status != model.Waiting {
		t.Fatalf("cancelled decision changed request: %#v %v", item, err)
	}
	approval, err := store.ApprovalFor(submitted.RequestId)
	if err != nil || approval != nil {
		t.Fatalf("cancelled decision persisted approval: %#v %v", approval, err)
	}
	if err := store.Transition(submitted.RequestId, model.PolicyRejected, model.Waiting); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: submitted.RequestId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("terminal request without a decision returned %v", err)
	}
}

func TestExistingDecisionFailsClosedOnCorruptOrUnavailableState(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	request := testExecutionRequest(t, "corrupt-existing-decision", "/bin/true", nil, time.Now().Add(time.Minute))
	hash, err := securejson.Hash(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		Version: 1, ApprovalID: "corrupt-existing-approval", RequestID: request.RequestID,
		RequestHash: "wrong-hash", Decision: "approve", ApprovedBy: model.ApprovedBy{Subject: "uid:0"},
		ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	item, err := store.Get(request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.existingDecision(item, "approve"); found || status.Code(err) != codes.DataLoss {
		t.Fatalf("corrupt stored decision did not fail closed: found=%v err=%v", found, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.existingDecision(item, "approve"); found || err == nil {
		t.Fatalf("unavailable decision store was accepted: found=%v err=%v", found, err)
	}
}

func TestSubmissionAndWatcherLimits(t *testing.T) {
	service, _, _ := testService(t, "require-approval")
	service.Config.MaxConcurrentPerUID = 1
	service.Config.MaxConcurrentTotal = 1
	service.Config.MaxSubmissionsPerMinute = 2
	if err := service.acquireSubmission(1000); err != nil {
		t.Fatal(err)
	}
	if err := service.acquireSubmission(1000); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("concurrent submission limit failed: %v", err)
	}
	service.releaseSubmission(1000)
	if err := service.acquireSubmission(1000); err != nil {
		t.Fatal(err)
	}
	service.releaseSubmission(1000)
	if err := service.acquireSubmission(1000); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("submission rate limit failed: %v", err)
	}

	service.Config.MaxWatchersPerUID = 1
	service.Config.MaxWatchersPerRequest = 1
	if err := service.acquireWatcher(1000, "request"); err != nil {
		t.Fatal(err)
	}
	if err := service.acquireWatcher(1000, "request"); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("watcher limit failed: %v", err)
	}
	service.releaseWatcher(1000, "request")
	if len(service.watchersByUID) != 0 || len(service.watchersByRequest) != 0 {
		t.Fatal("released watcher counters were retained")
	}
}

func testExecutionRequest(t *testing.T, id, executable string, argv []string, expires time.Time) model.ExecutionRequest {
	t.Helper()
	resolved, err := integrity.ResolveExecutable(executable, "/")
	if err != nil {
		t.Fatal(err)
	}
	executableMetadata, err := integrity.InspectExecutable(resolved)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := integrity.InspectDirectory("/")
	if err != nil {
		t.Fatal(err)
	}
	request := model.ExecutionRequest{
		Version: 1, RequestID: id, Requester: model.Requester{UID: 1000, GID: 1000},
		Execution:          model.Execution{Executable: resolved, Argv: argv, Cwd: "/"},
		ExecutableMetadata: executableMetadata, WorkingDirectoryMetadata: directory,
		PolicyResult: "require-approval", Reason: "test", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano), Nonce: "nonce",
	}
	request.Risk = integrity.Risk(resolved, argv, false, nil)
	return request
}

func TestCancelAuthorizationAndStates(t *testing.T) {
	service, _, _ := testService(t, "require-approval")
	request, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Cancel(peerContext(1001, 1001), &shudov1.CancelRequest{RequestId: request.RequestId}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other user cancelled request: %v", err)
	}
	response, err := service.Cancel(peerContext(1000, 1000), &shudov1.CancelRequest{RequestId: request.RequestId})
	if err != nil || response.Status != model.Cancelled {
		t.Fatalf("owner cancel failed: %#v %v", response, err)
	}
	if _, err := service.Cancel(peerContext(1000, 1000), &shudov1.CancelRequest{RequestId: request.RequestId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("terminal request cancelled: %v", err)
	}
	if _, err := service.Cancel(peerContext(0, 0), &shudov1.CancelRequest{RequestId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing request cancelled: %v", err)
	}
	if _, err := service.Cancel(context.Background(), &shudov1.CancelRequest{RequestId: request.RequestId}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated cancellation accepted: %v", err)
	}
}

type testWatchStream struct {
	ctx     context.Context
	events  []*shudov1.LocalEvent
	sendErr error
}

func (s *testWatchStream) Send(event *shudov1.LocalEvent) error {
	s.events = append(s.events, event)
	return s.sendErr
}
func (s *testWatchStream) SetHeader(metadata.MD) error  { return nil }
func (s *testWatchStream) SendHeader(metadata.MD) error { return nil }
func (s *testWatchStream) SetTrailer(metadata.MD)       {}
func (s *testWatchStream) Context() context.Context     { return s.ctx }
func (s *testWatchStream) SendMsg(any) error            { return nil }
func (s *testWatchStream) RecvMsg(any) error            { return io.EOF }

func TestWatchReplaysOutputAndEnforcesOwnership(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	request := testExecutionRequest(t, "watch-output", "/bin/true", nil, time.Now().Add(time.Minute))
	hash, err := securejson.Hash(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(request.RequestID, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(request.RequestID, 0, "stdout", []byte("first"), 1024); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(request.RequestID, 1, "stderr", []byte("second"), 1024); err != nil {
		t.Fatal(err)
	}
	code := int32(0)
	if err := store.FinishExecution(request.RequestID, &code, ""); err != nil {
		t.Fatal(err)
	}
	service.Config.Output.LiveBytes = 5
	stream := &testWatchStream{ctx: peerContext(1000, 1000)}
	if err := service.Watch(&shudov1.WatchRequest{RequestId: request.RequestID}, stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.events) != 3 || string(stream.events[0].Data) != "first" || string(stream.events[1].Data) != "second" || stream.events[2].Type != "finished" || !stream.events[2].HasExitCode {
		t.Fatalf("watch events mismatch: %#v", stream.events)
	}
	if err := service.Watch(&shudov1.WatchRequest{RequestId: request.RequestID}, &testWatchStream{ctx: peerContext(1001, 1001)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other user watched request: %v", err)
	}
	if err := service.Watch(&shudov1.WatchRequest{RequestId: "missing"}, &testWatchStream{ctx: peerContext(0, 0)}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing request watched: %v", err)
	}
	if err := service.Watch(&shudov1.WatchRequest{RequestId: request.RequestID}, &testWatchStream{ctx: context.Background()}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated watch accepted: %v", err)
	}
	sendFailure := errors.New("send failed")
	if err := service.Watch(&shudov1.WatchRequest{RequestId: request.RequestID}, &testWatchStream{ctx: peerContext(1000, 1000), sendErr: sendFailure}); !errors.Is(err, sendFailure) {
		t.Fatalf("send failure ignored: %v", err)
	}

	pending := testExecutionRequest(t, "watch-cancelled-context", "/bin/true", nil, time.Now().Add(time.Minute))
	hash, _ = securejson.Hash(pending)
	if err := store.Create(pending, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(pending.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	cancelledContext, cancel := context.WithCancel(peerContext(1000, 1000))
	cancel()
	if err := service.Watch(&shudov1.WatchRequest{RequestId: pending.RequestID}, &testWatchStream{ctx: cancelledContext}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled watch did not stop: %v", err)
	}

	denied := testExecutionRequest(t, "watch-denied", "/bin/true", nil, time.Now().Add(time.Minute))
	hash, _ = securejson.Hash(denied)
	if err := store.Create(denied, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(denied.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{Version: 1, ApprovalID: "watch-denial", RequestID: denied.RequestID, RequestHash: hash, Decision: "deny", ApprovedBy: model.ApprovedBy{Subject: "uid:0"}, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	deniedStream := &testWatchStream{ctx: peerContext(0, 0)}
	if err := service.Watch(&shudov1.WatchRequest{RequestId: denied.RequestID}, deniedStream); err != nil {
		t.Fatal(err)
	}
	if len(deniedStream.events) != 1 || deniedStream.events[0].Decision != "deny" || deniedStream.events[0].ApprovedBy != "uid:0" {
		t.Fatalf("decision event mismatch: %#v", deniedStream.events)
	}
}

func TestExecutionFailureAndTimeout(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	failing, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/sh", "-c", "echo out; echo err >&2; exit 3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, failing.RequestId)); err != nil {
		t.Fatal(err)
	}
	if item := waitForStatus(t, store, failing.RequestId, true); item.Status != model.Failed {
		t.Fatalf("failing command status: %#v", item)
	}
	execution, err := store.Execution(failing.RequestId)
	if err != nil || execution.ExitCode == nil || *execution.ExitCode != 3 {
		t.Fatalf("exit code missing: %#v %v", execution, err)
	}

	service.Config.MaxExecutionSeconds = 5
	timedInput := validSubmit("/bin/sleep", "2")
	timedInput.TimeoutMs = 1000
	timed, err := service.Submit(peerContext(1000, 1000), timedInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, timed.RequestId)); err != nil {
		t.Fatal(err)
	}
	if item := waitForStatus(t, store, timed.RequestId, true); item.Status != model.Failed {
		t.Fatalf("timed command status: %#v", item)
	}
	execution, err = store.Execution(timed.RequestId)
	if err != nil || execution.Signal != "EXECUTION_TIMEOUT" {
		t.Fatalf("timeout signal missing: %#v %v", execution, err)
	}
}

func TestApprovedScriptUsesPinnedInterpreter(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	directory := t.TempDir()
	interpreter := filepath.Join(directory, "interpreter")
	data, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interpreter, data, 0755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "script")
	if err := os.WriteFile(script, []byte("#!"+interpreter+" -e\nprintf pinned-script\n"), 0755); err != nil {
		t.Fatal(err)
	}
	submitted, err := service.Submit(peerContext(1000, 1000), validSubmit(script))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, submitted.RequestId)); err != nil {
		t.Fatal(err)
	}
	if item := waitForStatus(t, store, submitted.RequestId, true); item.Status != model.Succeeded {
		t.Fatalf("approved script failed: %#v", item)
	}
	chunks, err := store.Output(submitted.RequestId)
	if err != nil || len(chunks) != 1 || string(chunks[0].Data) != "pinned-script" {
		t.Fatalf("script output mismatch: %#v %v", chunks, err)
	}
}

func TestExecutionRejectsExpiredAndMismatchedApproval(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	expired := testExecutionRequest(t, "expired-execute", "/bin/true", nil, time.Now().Add(-time.Second))
	hash, _ := securejson.Hash(expired)
	persistApproved(t, store, expired, hash)
	service.execute(expired.RequestID)
	item, _ := store.Get(expired.RequestID)
	if item.Status != model.Expired {
		t.Fatalf("expired request status: %#v", item)
	}

	mismatch := testExecutionRequest(t, "approval-mismatch", "/bin/true", nil, time.Now().Add(time.Minute))
	hash, _ = securejson.Hash(mismatch)
	if err := store.Create(mismatch, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(mismatch.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{Version: 1, ApprovalID: "mismatch", RequestID: mismatch.RequestID, RequestHash: "wrong", Decision: "approve", ApprovedBy: model.ApprovedBy{Subject: "uid:0"}, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	service.execute(mismatch.RequestID)
	item, _ = store.Get(mismatch.RequestID)
	if item.Status != model.PolicyRejected {
		t.Fatalf("mismatched approval status: %#v", item)
	}
	service.execute("missing")
}

func TestExecutionSecurityGuardFailures(t *testing.T) {
	t.Run("concurrent guard", func(t *testing.T) {
		service, _, _ := testService(t, "require-approval")
		service.executing.Store("busy", struct{}{})
		service.execute("busy")
	})

	tests := []struct {
		name   string
		mutate func(*testing.T, *Service, *state.Store, *model.ExecutionRequest, *string)
	}{
		{"request hash", func(_ *testing.T, _ *Service, _ *state.Store, _ *model.ExecutionRequest, hash *string) {
			*hash = "wrong"
		}},
		{"invalid policy", func(t *testing.T, service *Service, _ *state.Store, _ *model.ExecutionRequest, _ *string) {
			if err := os.WriteFile(service.Config.PolicyPath, []byte("invalid: ["), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"deny policy", func(t *testing.T, service *Service, _ *state.Store, _ *model.ExecutionRequest, _ *string) {
			writeTestPolicy(t, service.Config.PolicyPath, "deny")
		}},
		{"directory", func(_ *testing.T, _ *Service, _ *state.Store, request *model.ExecutionRequest, _ *string) {
			request.WorkingDirectoryMetadata.Inode++
		}},
		{"executable", func(_ *testing.T, _ *Service, _ *state.Store, request *model.ExecutionRequest, _ *string) {
			request.ExecutableMetadata.SHA256 = "changed"
		}},
		{"environment", func(_ *testing.T, service *Service, _ *state.Store, request *model.ExecutionRequest, _ *string) {
			request.Execution.Env = map[string]string{"NOT_ALLOWED": "x"}
			service.Config.AllowedEnvironment = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, store, _ := testService(t, "require-approval")
			request := testExecutionRequest(t, "guard-"+strings.ReplaceAll(test.name, " ", "-"), "/bin/true", nil, time.Now().Add(time.Minute))
			hash, _ := securejson.Hash(request)
			test.mutate(t, service, store, &request, &hash)
			if test.name != "request hash" {
				hash, _ = securejson.Hash(request)
			}
			persistApproved(t, store, request, hash)
			service.execute(request.RequestID)
			item, err := store.Get(request.RequestID)
			if err != nil || item.Status != model.PolicyRejected {
				t.Fatalf("guard failure did not reject: %#v %v", item, err)
			}
		})
	}

	service, store, _ := testService(t, "require-approval")
	request := testExecutionRequest(t, "wrong-state", "/bin/true", nil, time.Now().Add(time.Minute))
	hash, _ := securejson.Hash(request)
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	service.execute(request.RequestID)
	item, _ := store.Get(request.RequestID)
	if item.Status != model.Waiting {
		t.Fatalf("failed BeginExecution changed state: %#v", item)
	}
}

func TestExecutionSanitizationAndCommandSetupFailures(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	request := testExecutionRequest(t, "bad-approved-environment", "/bin/true", nil, time.Now().Add(time.Minute))
	request.Execution.Env = map[string]string{"NOT_ALLOWED": "x"}
	hash, _ := securejson.Hash(request)
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{Version: 1, ApprovalID: "bad-env", RequestID: request.RequestID, RequestHash: hash, Decision: "approve", ApprovedBy: model.ApprovedBy{Subject: "uid:0"}, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	service.execute(request.RequestID)
	item, _ := store.Get(request.RequestID)
	if item.Status != model.PolicyRejected {
		t.Fatalf("invalid approved environment executed: %#v", item)
	}

	factories := []struct {
		name    string
		factory func(string, ...string) *exec.Cmd
	}{
		{"stdout pipe", func(string, ...string) *exec.Cmd {
			command := exec.Command("/bin/true")
			command.Stdout = io.Discard
			return command
		}},
		{"stderr pipe", func(string, ...string) *exec.Cmd {
			command := exec.Command("/bin/true")
			command.Stderr = io.Discard
			return command
		}},
		{"start", func(string, ...string) *exec.Cmd { return exec.Command("/definitely/missing/shudo-helper") }},
	}
	for _, test := range factories {
		t.Run(test.name, func(t *testing.T) {
			service, store, _ := testService(t, "require-approval")
			service.commandFactory = test.factory
			request := testExecutionRequest(t, "command-"+strings.ReplaceAll(test.name, " ", "-"), "/bin/true", nil, time.Now().Add(time.Minute))
			hash, _ := securejson.Hash(request)
			persistApproved(t, store, request, hash)
			service.execute(request.RequestID)
			item, err := store.Get(request.RequestID)
			if err != nil || item.Status != model.Failed {
				t.Fatalf("command setup failure not recorded: %#v %v", item, err)
			}
			execution, err := store.Execution(request.RequestID)
			if err != nil || execution.ExitCode == nil || *execution.ExitCode != 127 {
				t.Fatalf("setup exit code mismatch: %#v %v", execution, err)
			}
		})
	}
}

func TestReviewHistoryErrorsAndRecovery(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	first, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Submit(peerContext(1001, 1001), validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}
	history, err := service.ListRequests(peerContext(0, 0), &shudov1.ListRequestsRequest{IncludeHistory: true})
	if err != nil || len(history.Requests) != 2 {
		t.Fatalf("history failed: %#v %v", history, err)
	}
	if _, err := service.InspectRequest(peerContext(0, 0), &shudov1.InspectRequestRequest{RequestId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing inspection mismatch: %v", err)
	}
	if _, err := service.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: first.RequestId, Reason: "reviewed"}); err != nil {
		t.Fatal(err)
	}
	record, err := service.InspectRequest(peerContext(0, 0), &shudov1.InspectRequestRequest{RequestId: first.RequestId})
	if err != nil || record.DecisionReason != "reviewed" || record.DecidedBy == "" || record.Decision != "deny" || record.ApprovalId == "" {
		t.Fatalf("decision missing from record: %#v %v", record, err)
	}

	item, _ := store.Get(second.RequestId)
	approval := model.Approval{Version: 1, ApprovalID: "recover", RequestID: second.RequestId, RequestHash: item.RequestHash, Decision: "approve", ApprovedBy: model.ApprovedBy{Subject: "uid:0"}, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	service.RecoverApproved()
	if item := waitForStatus(t, store, second.RequestId, true); item.Status != model.Succeeded {
		t.Fatalf("approved recovery failed: %#v", item)
	}

	closedService, closedStore, _ := testService(t, "require-approval")
	if err := closedStore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := closedService.ListRequests(peerContext(0, 0), &shudov1.ListRequestsRequest{}); err == nil {
		t.Fatal("closed store list succeeded")
	}
	if _, err := closedService.Submit(peerContext(1000, 1000), validSubmit("/bin/true")); err == nil {
		t.Fatal("closed store submit succeeded")
	}
	if err := closedService.Watch(&shudov1.WatchRequest{RequestId: "x"}, &testWatchStream{ctx: peerContext(0, 0)}); err == nil {
		t.Fatal("closed store watch succeeded")
	}
	if _, err := closedService.InspectRequest(peerContext(0, 0), &shudov1.InspectRequestRequest{RequestId: "x"}); err == nil {
		t.Fatal("closed store inspect succeeded")
	}
	if _, err := closedService.Cancel(peerContext(0, 0), &shudov1.CancelRequest{RequestId: "x"}); err == nil {
		t.Fatal("closed store cancel succeeded")
	}
	if _, err := closedService.Deny(peerContext(0, 0), &shudov1.DecisionRequest{RequestId: "x"}); err == nil {
		t.Fatal("closed store decision succeeded")
	}
	closedService.RecoverApproved()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { closedService.RunMaintenance(ctx); close(done) }()
	time.Sleep(1100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed-store maintenance did not stop")
	}
}

func TestRequestRecordHelpersAndMaintenance(t *testing.T) {
	service, store, _ := testService(t, "require-approval")
	username, group := "alice", "users"
	request := testExecutionRequest(t, "record", "/bin/sh", []string{"-c", "true"}, time.Now().Add(time.Minute))
	request.Requester.Username, request.Requester.GroupName = &username, &group
	request.Execution.Env = map[string]string{"TERM": "xterm"}
	hash, _ := securejson.Hash(request)
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	item, _ := store.Get(request.RequestID)
	record := service.requestRecord(item)
	if record.RequesterUsername != username || record.RequesterGroup != group || record.Env["TERM"] != "xterm" {
		t.Fatalf("record fields missing: %#v", record)
	}
	if cloneMap(nil) != nil {
		t.Fatal("nil map clone mismatch")
	}
	original := map[string]string{"a": "b"}
	cloned := cloneMap(original)
	cloned["a"] = "c"
	if original["a"] != "b" {
		t.Fatal("map clone aliased input")
	}
	if hostname() == "" || approvalActor(model.Approval{ApprovedBy: model.ApprovedBy{Subject: "uid:0"}}) != "uid:0" {
		t.Fatal("display helper mismatch")
	}
	empty := ""
	if approvalActor(model.Approval{ApprovedBy: model.ApprovedBy{Subject: "fallback", DisplayName: &empty}}) != "fallback" {
		t.Fatal("empty display name did not fall back")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { service.RunMaintenance(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not stop")
	}
}
