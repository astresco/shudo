//go:build linux

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"
	"shudo.local/shudo/internal/integrity"
	"shudo.local/shudo/internal/localcreds"
	"shudo.local/shudo/internal/model"
	"shudo.local/shudo/internal/policy"
	"shudo.local/shudo/internal/securejson"
	"shudo.local/shudo/internal/state"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAdversarialRPCContractHasNoRemoteExecutionCapability(t *testing.T) {
	var methods []string
	for _, method := range shudov1.LocalBroker_ServiceDesc.Methods {
		methods = append(methods, method.MethodName)
	}
	for _, stream := range shudov1.LocalBroker_ServiceDesc.Streams {
		methods = append(methods, stream.StreamName)
	}
	sort.Strings(methods)
	want := []string{"Approve", "Cancel", "Deny", "InspectRequest", "ListRequests", "Submit", "Watch"}
	if !reflect.DeepEqual(methods, want) {
		t.Fatalf("unexpected broker RPC surface: got %v, want %v", methods, want)
	}
	for _, method := range methods {
		lower := strings.ToLower(method)
		if lower == "execute" || lower == "exec" || lower == "run" || lower == "command" {
			t.Fatalf("generic execution RPC exposed: %s", method)
		}
	}

	decisionFields := (&shudov1.DecisionRequest{}).ProtoReflect().Descriptor().Fields()
	var decisionFieldNames []string
	for index := 0; index < decisionFields.Len(); index++ {
		decisionFieldNames = append(decisionFieldNames, string(decisionFields.Get(index).Name()))
	}
	sort.Strings(decisionFieldNames)
	if want := []string{"reason", "request_hash", "request_id"}; !reflect.DeepEqual(decisionFieldNames, want) {
		t.Fatalf("decision message gained unexpected authority-bearing fields: got %v, want %v", decisionFieldNames, want)
	}
	submitFields := (&shudov1.SubmitRequest{}).ProtoReflect().Descriptor().Fields()
	var submitFieldNames []string
	for index := 0; index < submitFields.Len(); index++ {
		submitFieldNames = append(submitFieldNames, string(submitFields.Get(index).Name()))
	}
	sort.Strings(submitFieldNames)
	if want := []string{"argv", "cwd", "env", "executable", "reason", "timeout_ms"}; !reflect.DeepEqual(submitFieldNames, want) {
		t.Fatalf("submit message gained identity/decision fields: got %v, want %v", submitFieldNames, want)
	}
}

func TestAdversarialUnixTransportIgnoresForgedRootMetadata(t *testing.T) {
	service, store, _ := testService(t, policy.RequireApproval)
	// Go's root test harness creates its shared temporary parent with mode 0700.
	// Put this directory directly below /tmp so the credential-dropped helper can
	// traverse to the deliberately world-accessible test socket.
	directory, err := os.MkdirTemp("/tmp", "shudo-adversarial-transport-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	// Authorization must remain secure even if socket filesystem permissions are
	// accidentally too broad.
	if err := os.Chmod(socket, 0777); err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.Creds(localcreds.New()),
		grpc.MaxRecvMsgSize(512*1024),
		grpc.MaxSendMsgSize(2*1024*1024),
	)
	shudov1.RegisterLocalBrokerServer(server, service)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveDone
	})
	attackerUID, attackerGID := uint32(os.Getuid()), uint32(os.Getgid())
	if os.Geteuid() == 0 {
		attackerUID, attackerGID = 65534, 65534
		helperPath := filepath.Join(directory, "unprivileged-test-client")
		copyExecutable(t, os.Args[0], helperPath)
		command := exec.Command(helperPath, "-test.run=^TestAdversarialUnprivilegedClientHelper$")
		command.Env = append(os.Environ(), "SHUDO_ADVERSARIAL_SOCKET="+socket)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: attackerUID, Gid: attackerGID, NoSetGroups: true,
		}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("credential-dropped attacker failed: %v\n%s", err, output)
		}
	} else {
		exerciseUnprivilegedTransportAttacks(t, socket)
	}
	items, err := store.All()
	if err != nil || len(items) != 1 {
		t.Fatalf("attacker submission missing: %#v %v", items, err)
	}
	if items[0].Request.Requester.UID != attackerUID || items[0].Request.Requester.GID != attackerGID {
		t.Fatalf("metadata forged peer identity: %#v", items[0].Request.Requester)
	}
}

func TestAdversarialUnprivilegedClientHelper(t *testing.T) {
	socket := os.Getenv("SHUDO_ADVERSARIAL_SOCKET")
	if socket == "" {
		return
	}
	exerciseUnprivilegedTransportAttacks(t, socket)
}

func exerciseUnprivilegedTransportAttacks(t *testing.T, socket string) {
	t.Helper()
	connection, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := shudov1.NewLocalBrokerClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"x-shudo-uid", "0",
		"x-shudo-gid", "0",
		"x-shudo-role", "root",
		"authorization", "Bearer forged-root-token",
	))

	submitted, err := client.Submit(ctx, validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}

	attacks := []struct {
		name string
		call func() error
	}{
		{"list", func() error { _, err := client.ListRequests(ctx, &shudov1.ListRequestsRequest{}); return err }},
		{"inspect", func() error {
			_, err := client.InspectRequest(ctx, &shudov1.InspectRequestRequest{RequestId: submitted.RequestId})
			return err
		}},
		{"approve", func() error {
			_, err := client.Approve(ctx, &shudov1.DecisionRequest{RequestId: submitted.RequestId})
			return err
		}},
		{"deny", func() error {
			_, err := client.Deny(ctx, &shudov1.DecisionRequest{RequestId: submitted.RequestId})
			return err
		}},
	}
	for _, attack := range attacks {
		if err := attack.call(); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s accepted forged root metadata: %v", attack.name, err)
		}
	}
	oversized := validSubmit("/bin/true")
	oversized.Reason = strings.Repeat("x", 600*1024)
	if _, err := client.Submit(ctx, oversized); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized transport message was not rejected before handling: %v", err)
	}
	if err := connection.Invoke(ctx, "/shudo.v1.LocalBroker/Execute", validSubmit("/bin/true"), &shudov1.SubmitResponse{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("unknown execution RPC did not fail closed: %v", err)
	}
}

func TestAdversarialConcurrentApprovalsAreIdempotent(t *testing.T) {
	service, store, _ := testService(t, policy.RequireApproval)
	submitted, err := service.Submit(peerContext(1000, 1000), validSubmit("/bin/true"))
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 24
	type result struct {
		response *shudov1.DecisionResponse
		err      error
	}
	results := make(chan result, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, approveErr := service.Approve(peerContext(0, 0), approvalRequest(t, service, submitted.RequestId))
			results <- result{response: response, err: approveErr}
		}()
	}
	wait.Wait()
	close(results)
	approvalID := ""
	for result := range results {
		if result.err != nil {
			t.Fatalf("idempotent concurrent approval failed: %v", result.err)
		}
		if approvalID == "" {
			approvalID = result.response.ApprovalId
		}
		if result.response.ApprovalId != approvalID || result.response.Status != model.Approved {
			t.Fatalf("concurrent approval returned a different decision: %#v", result.response)
		}
	}
	if item := waitForStatus(t, store, submitted.RequestId, true); item.Status != model.Succeeded {
		t.Fatalf("single winning approval did not execute once: %#v", item)
	}
	approval, err := store.ApprovalFor(submitted.RequestId)
	if err != nil || approval == nil || approval.Decision != "approve" {
		t.Fatalf("winning approval missing: %#v %v", approval, err)
	}
}

func TestAdversarialApprovalCannotBeReboundOrChangeMeaning(t *testing.T) {
	tests := []struct {
		name           string
		rejectOnIngest bool
		approval       func(request model.ExecutionRequest, requestHash, otherHash string) model.Approval
	}{
		{
			name: "hash from another request",
			approval: func(request model.ExecutionRequest, _, otherHash string) model.Approval {
				return adversarialApproval("cross-bound", request.RequestID, otherHash, "approve")
			},
		},
		{
			name:           "non-approval decision",
			rejectOnIngest: true,
			approval: func(request model.ExecutionRequest, requestHash, _ string) model.Approval {
				return adversarialApproval("invalid-decision", request.RequestID, requestHash, "allow-forever")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, store, _ := testService(t, policy.RequireApproval)
			other := testExecutionRequest(t, "other-request", "/bin/true", nil, time.Now().Add(time.Minute))
			otherHash, err := securejson.Hash(other)
			if err != nil {
				t.Fatal(err)
			}
			request := testExecutionRequest(t, "target-request", "/bin/true", nil, time.Now().Add(time.Minute))
			requestHash, err := securejson.Hash(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Create(request, requestHash); err != nil {
				t.Fatal(err)
			}
			if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
				t.Fatal(err)
			}
			acceptErr := store.AcceptApproval(test.approval(request, requestHash, otherHash))
			if test.rejectOnIngest {
				if acceptErr == nil {
					t.Fatal("malformed approval was persisted")
				}
				item, err := store.Get(request.RequestID)
				if err != nil || item == nil || item.Status != model.Waiting {
					t.Fatalf("rejected approval changed request: %#v %v", item, err)
				}
				return
			}
			if acceptErr != nil {
				t.Fatal(acceptErr)
			}
			service.execute(request.RequestID)
			item, err := store.Get(request.RequestID)
			if err != nil || item == nil || item.Status != model.PolicyRejected {
				t.Fatalf("rebound approval was not rejected: %#v %v", item, err)
			}
			if execution, err := store.Execution(request.RequestID); err != nil || execution != nil {
				t.Fatalf("rebound approval reached execution: %#v %v", execution, err)
			}
		})
	}
}

func TestAdversarialPolicyDenyAfterApprovalPreventsExecution(t *testing.T) {
	service, store, policyPath := testService(t, policy.RequireApproval)
	marker := filepath.Join(t.TempDir(), "policy-bypass-marker")
	request := testExecutionRequest(t, "policy-revoked", "/usr/bin/touch", []string{marker}, time.Now().Add(time.Minute))
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
	if err := store.AcceptApproval(adversarialApproval("approved-before-deny", request.RequestID, hash, "approve")); err != nil {
		t.Fatal(err)
	}
	writeTestPolicy(t, policyPath, policy.Deny)
	service.execute(request.RequestID)
	assertRejectedWithoutMarker(t, store, request.RequestID, marker)
}

func TestAdversarialExecutableAndDirectoryReplacementNeverRuns(t *testing.T) {
	t.Run("executable replacement", func(t *testing.T) {
		service, store, _ := testService(t, policy.RequireApproval)
		directory := t.TempDir()
		executable := filepath.Join(directory, "approved-tool")
		copyExecutable(t, "/usr/bin/true", executable)
		marker := filepath.Join(directory, "replacement-ran")
		request := testExecutionRequest(t, "executable-swap", executable, []string{marker}, time.Now().Add(time.Minute))
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
		if err := store.AcceptApproval(adversarialApproval("before-executable-swap", request.RequestID, hash, "approve")); err != nil {
			t.Fatal(err)
		}
		replacement := filepath.Join(directory, "replacement")
		copyExecutable(t, "/usr/bin/touch", replacement)
		if err := os.Rename(replacement, executable); err != nil {
			t.Fatal(err)
		}
		service.execute(request.RequestID)
		assertRejectedWithoutMarker(t, store, request.RequestID, marker)
	})

	t.Run("working directory replacement", func(t *testing.T) {
		service, store, _ := testService(t, policy.RequireApproval)
		parent := t.TempDir()
		working := filepath.Join(parent, "approved-working-directory")
		if err := os.Mkdir(working, 0700); err != nil {
			t.Fatal(err)
		}
		request := testExecutionRequest(t, "directory-swap", "/usr/bin/touch", []string{"replacement-ran"}, time.Now().Add(time.Minute))
		request.Execution.Cwd = working
		request.WorkingDirectoryMetadata, _ = integrity.InspectDirectory(working)
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
		if err := store.AcceptApproval(adversarialApproval("before-directory-swap", request.RequestID, hash, "approve")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(working, working+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(working, 0700); err != nil {
			t.Fatal(err)
		}
		service.execute(request.RequestID)
		assertRejectedWithoutMarker(t, store, request.RequestID, filepath.Join(working, "replacement-ran"))
	})
}

func TestAdversarialShellMetacharactersRemainLiteralArguments(t *testing.T) {
	service, store, _ := testService(t, policy.RequireApproval)
	marker := filepath.Join(t.TempDir(), "shell-injection-marker")
	payload := fmt.Sprintf("$(touch %s); `touch %s`; | /usr/bin/id", marker, marker)
	submitted, err := service.Submit(peerContext(1000, 1000), validSubmit("/usr/bin/printf", "%s", payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(peerContext(0, 0), approvalRequest(t, service, submitted.RequestId)); err != nil {
		t.Fatal(err)
	}
	if item := waitForStatus(t, store, submitted.RequestId, true); item.Status != model.Succeeded {
		t.Fatalf("literal printf failed: %#v", item)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("shell metacharacters executed; marker stat error: %v", err)
	}
	chunks, err := store.Output(submitted.RequestId)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	for _, chunk := range chunks {
		if chunk.Stream == "stdout" {
			output.Write(chunk.Data)
		}
	}
	if output.String() != payload {
		t.Fatalf("argument was not passed literally: got %q, want %q", output.String(), payload)
	}
}

func adversarialApproval(id, requestID, requestHash, decision string) model.Approval {
	return model.Approval{
		Version: 1, ApprovalID: id, RequestID: requestID, RequestHash: requestHash,
		Decision: decision, ApprovedBy: model.ApprovedBy{Subject: "uid:0"},
		ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func copyExecutable(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0755); err != nil {
		t.Fatal(err)
	}
}

func assertRejectedWithoutMarker(t *testing.T, store interface {
	Get(string) (*state.StoredRequest, error)
	Execution(string) (*state.ExecutionResult, error)
}, requestID, marker string) {
	t.Helper()
	item, err := store.Get(requestID)
	if err != nil || item == nil || item.Status != model.PolicyRejected {
		t.Fatalf("attack was not rejected: %#v %v", item, err)
	}
	if execution, err := store.Execution(requestID); err != nil || execution != nil {
		t.Fatalf("attack reached execution: %#v %v", execution, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("attack created marker %s: %v", marker, err)
	}
}
