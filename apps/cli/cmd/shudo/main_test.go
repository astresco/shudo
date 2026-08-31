//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFriendlyTrimsTransportWhitespace(t *testing.T) {
	if got := friendly(errors.New("\n transport failed \n")); got != "transport failed" {
		t.Fatalf("got %q", got)
	}
}

func TestRetryableWatchError(t *testing.T) {
	for _, err := range []error{io.EOF, status.Error(codes.Unavailable, "restart"), status.Error(codes.Internal, "transport closed")} {
		if !retryableWatchError(err) {
			t.Fatalf("expected %v to be retryable", err)
		}
	}
	if retryableWatchError(status.Error(codes.PermissionDenied, "wrong user")) {
		t.Fatal("permission failures must not be retried")
	}
}

func TestAmbiguousDecisionErrors(t *testing.T) {
	for _, code := range []codes.Code{codes.Canceled, codes.DeadlineExceeded, codes.Unknown, codes.Internal, codes.Unavailable} {
		if !ambiguousDecisionError(status.Error(code, "lost response")) {
			t.Fatalf("%s was not treated as ambiguous", code)
		}
	}
	if ambiguousDecisionError(status.Error(codes.FailedPrecondition, "definitive rejection")) {
		t.Fatal("definitive rejection was treated as ambiguous")
	}
}

func TestDecisionResponseFromAuthoritativeRecord(t *testing.T) {
	request := &shudov1.DecisionRequest{RequestId: "request", RequestHash: "hash"}
	record := &shudov1.RequestRecord{
		RequestId: "request", RequestHash: "hash", Status: "SUCCEEDED",
		Decision: "approve", ApprovalId: "approval", DecidedBy: "root",
	}
	response, err := decisionResponseFromRecord(record, request, "approve")
	if err != nil || response.ApprovalId != "approval" || response.Status != "APPROVED" {
		t.Fatalf("committed approval was not reconciled: %#v %v", response, err)
	}
	denied := &shudov1.RequestRecord{RequestId: "request", Status: "DENIED", Decision: "deny", ApprovalId: "denial"}
	response, err = decisionResponseFromRecord(denied, &shudov1.DecisionRequest{RequestId: "request"}, "deny")
	if err != nil || response.Status != "DENIED" {
		t.Fatalf("committed denial was not reconciled: %#v %v", response, err)
	}
	for name, candidate := range map[string]*shudov1.RequestRecord{
		"pending":          {RequestId: "request", RequestHash: "hash", Status: "WAITING_APPROVAL"},
		"conflicting":      {RequestId: "request", RequestHash: "hash", Decision: "deny", ApprovalId: "denial"},
		"missing approval": {RequestId: "request", RequestHash: "hash", Decision: "approve"},
		"wrong hash":       {RequestId: "request", RequestHash: "other", Decision: "approve", ApprovalId: "approval"},
	} {
		if _, err := decisionResponseFromRecord(candidate, request, "approve"); err == nil {
			t.Fatalf("%s reconciliation was accepted", name)
		}
	}
}

func TestReviewParsing(t *testing.T) {
	options, ok, err := parseAdmin([]string{"--approve", "request-a", "--confirm-hash", "full-hash"})
	if err != nil || !ok || options.operation != "approve" || options.requestID != "request-a" || options.reason != "" || options.confirmHash != "full-hash" {
		t.Fatalf("unexpected approval parse: %#v %v %v", options, ok, err)
	}
	options, ok, err = parseAdmin([]string{"--requests", "--json"})
	if err != nil || !ok || options.operation != "history" || !options.json {
		t.Fatalf("unexpected request-list parse: %#v %v", options, err)
	}
	options, ok, err = parseAdmin([]string{"--approve"})
	if err != nil || !ok || options.operation != "approve" || options.requestID != "" {
		t.Fatalf("interactive approval did not parse: %#v %v", options, err)
	}
}

func TestReviewParsingRejectsInvalidOptions(t *testing.T) {
	for _, arguments := range [][]string{
		{"--approve", "--reason"},
		{"--approve", "request", "--confirm-hash"},
		{"--deny", "request", "--confirm-hash", "hash"},
		{"--pending", "--reason", "not-valid-for-listing"},
		{"--show", "id", "--unexpected"},
	} {
		if _, ok, err := parseAdmin(arguments); !ok || err == nil {
			t.Fatalf("invalid review arguments accepted: %#v", arguments)
		}
	}
	if _, ok, err := parseAdmin(nil); ok || err != nil {
		t.Fatalf("empty arguments identified as review command: %v", err)
	}
	if _, ok, err := parseAdmin([]string{"/usr/bin/id"}); ok || err != nil {
		t.Fatalf("ordinary command identified as review command: %v", err)
	}
}

func TestVerboseApprovalDocketContainsExactRequest(t *testing.T) {
	record := &shudov1.RequestRecord{
		RequestId: "request-id", RequestHash: "request-hash", Status: "WAITING_APPROVAL",
		RequesterUid: 1000, RequesterGid: 100, Executable: "/usr/bin/printf",
		Argv: []string{"line\nvalue"}, Command: "/usr/bin/printf line", Cwd: "/tmp", Reason: "test",
	}
	var output strings.Builder
	printRecordTo(&output, record, true)
	for _, required := range []string{"request-id", "request-hash", "/usr/bin/printf", `"line\nvalue"`, "1000/100"} {
		if !strings.Contains(output.String(), required) {
			t.Fatalf("approval docket omitted %q: %s", required, output.String())
		}
	}
}

func TestCommandParsing(t *testing.T) {
	parsed, err := parse([]string{"exec", "--reason", "test", "--timeout", "2m", "--detach", "--json", "--verbose", "--", "/usr/bin/printf", "-n", "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.reason != "test" || parsed.timeout != 2*time.Minute || !parsed.detach || !parsed.json || !parsed.verbose || !reflect.DeepEqual(parsed.command, []string{"/usr/bin/printf", "-n", "hello"}) {
		t.Fatalf("parsed options mismatch: %#v", parsed)
	}
	direct, err := parse([]string{"/usr/bin/id"})
	if err != nil || direct.timeout != 5*time.Minute || !reflect.DeepEqual(direct.command, []string{"/usr/bin/id"}) {
		t.Fatalf("direct command mismatch: %#v %v", direct, err)
	}
	dash, err := parse([]string{"-"})
	if err != nil || !reflect.DeepEqual(dash.command, []string{"-"}) {
		t.Fatalf("dash executable mismatch: %#v %v", dash, err)
	}
}

func TestCommandParsingRejectsInvalidOptions(t *testing.T) {
	for _, arguments := range [][]string{
		{},
		{"exec"},
		{"--reason"},
		{"--timeout"},
		{"--timeout", "garbage", "/bin/true"},
		{"--timeout", "999ms", "/bin/true"},
		{"--timeout", "25h", "/bin/true"},
		{"--env"},
		{"--env", "INVALID", "/bin/true"},
		{"--unknown", "/bin/true"},
		{"--help"},
	} {
		if _, err := parse(arguments); err == nil {
			t.Fatalf("invalid command arguments accepted: %#v", arguments)
		}
	}
}

func TestReviewRequiresRoot(t *testing.T) {
	if err := requireRootReview(1000); err == nil {
		t.Fatal("non-root review was allowed")
	}
	if err := requireRootReview(0); err != nil {
		t.Fatalf("root review was denied: %v", err)
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("b02fc4d5-6a7c-48ed-bfcd-103e56b4c84d"); got != "b02fc4d5" {
		t.Fatalf("got %q", got)
	}
}

func TestTerminalTextEscapesControls(t *testing.T) {
	if got := terminalText("approve\x1b[2Jspoof"); got != `"approve\x1b[2Jspoof"` {
		t.Fatalf("got %q", got)
	}
}

func TestSocketPathConfiguration(t *testing.T) {
	t.Setenv("SHUDO_SOCKET_PATH", "/tmp/shudo-test.sock")
	if got := localSocketPath(); got != "/tmp/shudo-test.sock" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("SHUDO_SOCKET_PATH", "relative.sock")
	if got := localSocketPath(); got != "/run/shudo/shudo.sock" {
		t.Fatalf("relative path produced %q", got)
	}
}

func TestRecordJSONPreservesReviewFields(t *testing.T) {
	record := &shudov1.RequestRecord{
		RequestId: "request", RequestHash: "hash", Status: "WAITING_APPROVAL",
		RequesterUid: 1000, RequesterGid: 100, RequesterUsername: "alice", RequesterGroup: "users",
		Executable: "/usr/bin/printf", Argv: []string{"hello"}, Command: "/usr/bin/printf hello",
		Cwd: "/tmp", Env: map[string]string{"TERM": "xterm"}, Reason: "test", Warnings: []string{"warning"},
		Decision: "approve", ApprovalId: "approval",
	}
	got := recordJSON(record)
	if got["requestId"] != "request" || got["command"] != "/usr/bin/printf hello" || got["reason"] != "test" {
		t.Fatalf("record JSON mismatch: %#v", got)
	}
	requester := got["requester"].(map[string]any)
	if requester["username"] != "alice" || requester["group"] != "users" {
		t.Fatalf("requester JSON mismatch: %#v", requester)
	}
	if records := recordsJSON([]*shudov1.RequestRecord{record}); len(records) != 1 || records[0]["requestHash"] != "hash" || records[0]["approvalId"] != "approval" {
		t.Fatalf("record list mismatch: %#v", records)
	}
}

func TestWatchCompletionHelpers(t *testing.T) {
	interrupted := make(chan struct{})
	code, err := watchContextResult(interrupted)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout result mismatch: %d %v", code, err)
	}
	close(interrupted)
	code, err = watchContextResult(interrupted)
	if code != 130 || err != nil {
		t.Fatalf("interrupt result mismatch: %d %v", code, err)
	}
	if retryableWatchError(status.Error(codes.InvalidArgument, "bad request")) {
		t.Fatal("invalid argument was treated as retryable")
	}
}

func TestFriendlyStatusAndRunParseFailure(t *testing.T) {
	if got := friendly(status.Error(codes.PermissionDenied, " denied ")); got != "denied" {
		t.Fatalf("friendly status mismatch: %q", got)
	}
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	os.Args = []string{"shudo", "--timeout", "invalid", "/bin/true"}
	code, err := run()
	if code != 2 || err == nil {
		t.Fatalf("parse failure mismatch: %d %v", code, err)
	}
	if got := usage(); !strings.Contains(got, "--pending") || !strings.Contains(got, "COMMAND") {
		t.Fatalf("usage is incomplete: %q", got)
	}
}
