package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"
	"shudo.local/shudo/internal/config"
	"shudo.local/shudo/internal/cryptoutil"
	"shudo.local/shudo/internal/integrity"
	"shudo.local/shudo/internal/localcreds"
	"shudo.local/shudo/internal/model"
	"shudo.local/shudo/internal/policy"
	"shudo.local/shudo/internal/securejson"
	"shudo.local/shudo/internal/state"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const Version = "0.3.0"

type Service struct {
	shudov1.UnimplementedLocalBrokerServer
	Config            config.Daemon
	Store             *state.Store
	executing         sync.Map
	submitMu          sync.Mutex
	limitMu           sync.Mutex
	submitting        map[uint32]int
	submittingTotal   int
	submissionTimes   map[uint32][]time.Time
	watchersByUID     map[uint32]int
	watchersByRequest map[string]int
	commandFactory    func(string, ...string) *exec.Cmd
}

func New(cfg config.Daemon, store *state.Store) (*Service, error) {
	if cfg.MaxConcurrentPerUID == 0 {
		cfg.MaxConcurrentPerUID = 2
	}
	if cfg.MaxConcurrentTotal == 0 {
		cfg.MaxConcurrentTotal = 32
	}
	if cfg.MaxSubmissionsPerMinute == 0 {
		cfg.MaxSubmissionsPerMinute = 60
	}
	if cfg.MaxWatchersPerUID == 0 {
		cfg.MaxWatchersPerUID = 8
	}
	if cfg.MaxWatchersPerRequest == 0 {
		cfg.MaxWatchersPerRequest = 4
	}
	if cfg.MaxExecutableBytes == 0 {
		cfg.MaxExecutableBytes = 256 * 1024 * 1024
	}
	if cfg.RetentionDays == 0 {
		cfg.RetentionDays = 30
	}
	if cfg.MaxRetainedUnapproved == 0 {
		cfg.MaxRetainedUnapproved = 10_000
	}
	store.SetMaxBytes(cfg.MaxDatabaseBytes)
	return &Service{
		Config: cfg, Store: store, submitting: map[uint32]int{}, submissionTimes: map[uint32][]time.Time{},
		watchersByUID: map[uint32]int{}, watchersByRequest: map[string]int{},
	}, nil
}

func requester(ctx context.Context) (model.Requester, error) {
	remote, ok := peer.FromContext(ctx)
	if !ok {
		return model.Requester{}, status.Error(codes.Unauthenticated, "missing Unix peer credentials")
	}
	auth, ok := remote.AuthInfo.(localcreds.AuthInfo)
	if !ok {
		return model.Requester{}, status.Error(codes.Unauthenticated, "invalid Unix peer credentials")
	}
	pid := auth.PID
	result := model.Requester{UID: auth.UID, GID: auth.GID, PID: &pid}
	if auth.Username != "" {
		result.Username = &auth.Username
	}
	if auth.GroupName != "" {
		result.GroupName = &auth.GroupName
	}
	return result, nil
}

func rootRequester(ctx context.Context) (model.Requester, error) {
	actor, err := requester(ctx)
	if err != nil {
		return model.Requester{}, err
	}
	if actor.UID != 0 {
		return model.Requester{}, status.Error(codes.PermissionDenied, "this operation requires a process currently running as root")
	}
	return actor, nil
}

func (s *Service) Submit(ctx context.Context, input *shudov1.SubmitRequest) (*shudov1.SubmitResponse, error) {
	actor, err := requester(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateSubmit(input); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.acquireSubmission(actor.UID); err != nil {
		return nil, err
	}
	defer s.releaseSubmission(actor.UID)
	if err := s.Store.ExpireOutstanding(); err != nil {
		return nil, err
	}
	s.submitMu.Lock()
	perUID, total, countErr := s.Store.OutstandingCounts(actor.UID)
	s.submitMu.Unlock()
	if countErr != nil {
		return nil, countErr
	}
	if perUID >= s.Config.MaxPendingPerUID || total >= s.Config.MaxPendingTotal {
		return nil, status.Error(codes.ResourceExhausted, "too many outstanding requests")
	}
	reason := strings.TrimSpace(input.GetReason())
	executable, err := integrity.ResolveExecutable(input.GetExecutable(), input.GetCwd())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	executableMetadata, interpreter, interpreterArgument, err := integrity.InspectExecutableAndInterpreter(executable, s.Config.MaxExecutableBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	workingDirectory, err := integrity.InspectDirectory(input.GetCwd())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	currentPolicy, err := policy.Load(s.Config.PolicyPath)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "local policy is invalid")
	}
	action := policy.Evaluate(currentPolicy, policy.Input{Executable: executable, Argv: input.GetArgv(), Cwd: workingDirectory.Path, UID: actor.UID})
	requestID, err := cryptoutil.UUID()
	if err != nil {
		return nil, err
	}
	nonce, err := cryptoutil.Nonce(24)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	request := model.ExecutionRequest{
		Version: 1, RequestID: requestID, Requester: actor,
		Execution:          model.Execution{Executable: executable, Argv: append([]string{}, input.GetArgv()...), Cwd: workingDirectory.Path, Env: cloneMap(input.GetEnv())},
		ExecutableMetadata: executableMetadata, InterpreterMetadata: interpreter, InterpreterArgument: interpreterArgument,
		WorkingDirectoryMetadata: workingDirectory, Risk: integrity.Risk(executable, input.GetArgv(), interpreter != nil, input.GetEnv()),
		PolicyResult: action, Reason: reason, CreatedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Duration(input.GetTimeoutMs()) * time.Millisecond).Format(time.RFC3339Nano), Nonce: nonce,
	}
	hash, err := securejson.Hash(request)
	if err != nil {
		return nil, err
	}
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	perUID, total, err = s.Store.OutstandingCounts(actor.UID)
	if err != nil {
		return nil, err
	}
	if perUID >= s.Config.MaxPendingPerUID || total >= s.Config.MaxPendingTotal {
		return nil, status.Error(codes.ResourceExhausted, "too many outstanding requests")
	}
	if err := s.Store.Create(request, hash); err != nil {
		if err == state.ErrStorageLimit {
			return nil, status.Error(codes.ResourceExhausted, "state storage limit reached")
		}
		return nil, err
	}
	switch action {
	case policy.Deny:
		if err := s.Store.Transition(requestID, model.PolicyRejected, model.Created); err != nil {
			return nil, err
		}
	default:
		if err := s.Store.Transition(requestID, model.Waiting, model.Created); err != nil {
			return nil, err
		}
	}
	stored, _ := s.Store.Get(requestID)
	return &shudov1.SubmitResponse{RequestId: requestID, RequestHash: hash, Status: stored.Status, Hostname: hostname(), Command: command(executable, input.GetArgv())}, nil
}

func (s *Service) Watch(input *shudov1.WatchRequest, stream shudov1.LocalBroker_WatchServer) error {
	actor, err := requester(stream.Context())
	if err != nil {
		return err
	}
	item, err := s.Store.Get(input.GetRequestId())
	if err != nil {
		return err
	}
	if item == nil {
		return status.Error(codes.NotFound, "request not found")
	}
	if actor.UID != 0 && actor.UID != item.Request.Requester.UID {
		return status.Error(codes.PermissionDenied, "request belongs to another local user")
	}
	if err := s.acquireWatcher(actor.UID, item.Request.RequestID); err != nil {
		return err
	}
	defer s.releaseWatcher(actor.UID, item.Request.RequestID)
	after := input.GetAfterSequence()
	for {
		if err := s.Store.ExpireOutstanding(); err != nil {
			return err
		}
		chunks, more, err := s.Store.OutputAfter(input.GetRequestId(), after, s.Config.Output.LiveBytes)
		if err != nil {
			return err
		}
		for _, chunk := range chunks {
			if err := stream.Send(&shudov1.LocalEvent{Type: "output", RequestId: input.GetRequestId(), Stream: chunk.Stream, Data: chunk.Data, Sequence: chunk.Sequence}); err != nil {
				return err
			}
			after = chunk.Sequence + 1
		}
		if more {
			continue
		}
		item, err = s.Store.Get(input.GetRequestId())
		if err != nil {
			return err
		}
		if item == nil {
			return status.Error(codes.NotFound, "request not found")
		}
		approval, _ := s.Store.ApprovalFor(input.GetRequestId())
		event := &shudov1.LocalEvent{Type: "state", RequestId: input.GetRequestId(), Status: item.Status, Truncated: item.OutputTruncated}
		if approval != nil {
			event.Decision = approval.Decision
			event.ApprovedBy = approvalActor(*approval)
		}
		if model.Terminal(item.Status) {
			if execution, _ := s.Store.Execution(input.GetRequestId()); execution != nil {
				if execution.ExitCode != nil {
					event.HasExitCode = true
					event.ExitCode = *execution.ExitCode
				}
				event.Signal = execution.Signal
			}
			event.Type = "finished"
			return stream.Send(event)
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Service) ListRequests(ctx context.Context, input *shudov1.ListRequestsRequest) (*shudov1.ListRequestsResponse, error) {
	_, err := rootRequester(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Store.ExpireOutstanding(); err != nil {
		return nil, err
	}
	var items []state.StoredRequest
	if input.GetIncludeHistory() {
		items, err = s.Store.Recent(50, 0, true)
	} else {
		items, err = s.Store.RecentPending(256, 0, true)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Request.CreatedAt > items[j].Request.CreatedAt })
	result := &shudov1.ListRequestsResponse{Requests: make([]*shudov1.RequestRecord, 0, len(items))}
	for index := range items {
		result.Requests = append(result.Requests, s.requestRecord(&items[index]))
	}
	return result, nil
}

func (s *Service) InspectRequest(ctx context.Context, input *shudov1.InspectRequestRequest) (*shudov1.RequestRecord, error) {
	_, err := rootRequester(ctx)
	if err != nil {
		return nil, err
	}
	item, err := s.Store.Get(input.GetRequestId())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, status.Error(codes.NotFound, "request not found")
	}
	return s.requestRecord(item), nil
}

func (s *Service) Approve(ctx context.Context, input *shudov1.DecisionRequest) (*shudov1.DecisionResponse, error) {
	return s.decide(ctx, input, "approve")
}

func (s *Service) Deny(ctx context.Context, input *shudov1.DecisionRequest) (*shudov1.DecisionResponse, error) {
	return s.decide(ctx, input, "deny")
}

func (s *Service) decide(ctx context.Context, input *shudov1.DecisionRequest, decision string) (*shudov1.DecisionResponse, error) {
	actor, err := rootRequester(ctx)
	if err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(input.GetReason())
	if len(reason) > 4096 || strings.ContainsRune(reason, '\x00') {
		return nil, status.Error(codes.InvalidArgument, "invalid decision reason")
	}
	if err := s.Store.ExpireOutstanding(); err != nil {
		return nil, err
	}
	item, err := s.Store.Get(input.GetRequestId())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, status.Error(codes.NotFound, "request not found")
	}
	if decision == "approve" && !cryptoutil.Equal(input.GetRequestHash(), item.RequestHash) {
		return nil, status.Error(codes.FailedPrecondition, "approval must confirm the inspected request hash")
	}
	if item.Status != model.Waiting {
		if response, found, existingErr := s.existingDecision(item, decision); found || existingErr != nil {
			if found && decision == "approve" && item.Status == model.Approved {
				go s.execute(item.Request.RequestID)
			}
			return response, existingErr
		}
		return nil, status.Errorf(codes.FailedPrecondition, "request is %s, not awaiting approval", item.Status)
	}
	recomputed, err := securejson.Hash(item.Request)
	if err != nil || !cryptoutil.Equal(recomputed, item.RequestHash) {
		_ = s.Store.Transition(item.Request.RequestID, model.PolicyRejected, model.Waiting)
		_ = s.Store.RecordSecurityEvent("request.integrity-failed", item.Request.RequestID, item.RequestHash, "Persisted request hash mismatch during local decision")
		return nil, status.Error(codes.DataLoss, "persisted request integrity check failed")
	}
	approvalID, err := cryptoutil.UUID()
	if err != nil {
		return nil, err
	}
	displayName := actor.Username
	approval := model.Approval{
		Version: 1, ApprovalID: approvalID, RequestID: item.Request.RequestID,
		RequestHash: item.RequestHash, Decision: decision,
		ApprovedBy: model.ApprovedBy{Subject: "uid:0", DisplayName: displayName},
		ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano), Reason: reason,
	}
	if err := s.Store.AcceptApprovalContext(ctx, approval); err != nil {
		if response, found, existingErr := s.existingDecision(item, decision); found || existingErr != nil {
			return response, existingErr
		}
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return nil, status.Error(codes.Aborted, "request was decided concurrently")
	}
	eventType := "request.denied"
	if decision == "approve" {
		eventType = "request.approved"
	}
	detail := reason
	if detail == "" {
		detail = decision + "d by local uid 0"
	}
	_ = s.Store.RecordSecurityEvent(eventType, item.Request.RequestID, item.RequestHash, detail)
	next := model.Denied
	if decision == "approve" {
		next = model.Approved
		go s.execute(item.Request.RequestID)
	}
	return &shudov1.DecisionResponse{RequestId: item.Request.RequestID, ApprovalId: approvalID, Status: next, DecidedBy: approvalActor(approval)}, nil
}

func (s *Service) existingDecision(item *state.StoredRequest, decision string) (*shudov1.DecisionResponse, bool, error) {
	approval, err := s.Store.ApprovalFor(item.Request.RequestID)
	if err != nil {
		return nil, false, err
	}
	if approval == nil {
		return nil, false, nil
	}
	if !cryptoutil.Equal(approval.RequestID, item.Request.RequestID) ||
		!cryptoutil.Equal(approval.RequestHash, item.RequestHash) {
		return nil, false, status.Error(codes.DataLoss, "stored decision integrity check failed")
	}
	if approval.Decision != decision {
		return nil, false, status.Errorf(codes.FailedPrecondition, "request already has a conflicting %s decision", approval.Decision)
	}
	next := model.Denied
	if decision == "approve" {
		next = model.Approved
	}
	return &shudov1.DecisionResponse{
		RequestId: item.Request.RequestID, ApprovalId: approval.ApprovalID,
		Status: next, DecidedBy: approvalActor(*approval),
	}, true, nil
}

func (s *Service) requestRecord(item *state.StoredRequest) *shudov1.RequestRecord {
	record := &shudov1.RequestRecord{
		RequestId: item.Request.RequestID, RequestHash: item.RequestHash, Status: item.Status,
		RequesterUid: item.Request.Requester.UID, RequesterGid: item.Request.Requester.GID,
		Executable: item.Request.Execution.Executable, Argv: append([]string{}, item.Request.Execution.Argv...),
		Cwd: item.Request.Execution.Cwd, Env: cloneMap(item.Request.Execution.Env),
		Command: command(item.Request.Execution.Executable, item.Request.Execution.Argv), Reason: item.Request.Reason,
		CreatedAt: item.Request.CreatedAt, ExpiresAt: item.Request.ExpiresAt, PolicyResult: item.Request.PolicyResult,
		Shell: item.Request.Risk.Shell, Interpreter: item.Request.Risk.Interpreter, Script: item.Request.Risk.Script,
		Warnings: append([]string{}, item.Request.Risk.Warnings...),
	}
	if item.Request.Requester.Username != nil {
		record.RequesterUsername = *item.Request.Requester.Username
	}
	if item.Request.Requester.GroupName != nil {
		record.RequesterGroup = *item.Request.Requester.GroupName
	}
	if approval, _ := s.Store.ApprovalFor(item.Request.RequestID); approval != nil {
		record.DecidedBy = approvalActor(*approval)
		record.DecisionReason = approval.Reason
		record.Decision = approval.Decision
		record.ApprovalId = approval.ApprovalID
	}
	return record
}

func (s *Service) RunMaintenance(ctx context.Context) {
	expiryTicker := time.NewTicker(time.Second)
	retentionTicker := time.NewTicker(time.Hour)
	defer expiryTicker.Stop()
	defer retentionTicker.Stop()
	s.runRetentionMaintenance("initial")
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiryTicker.C:
			if err := s.Store.ExpireOutstanding(); err != nil {
				fmt.Fprintf(os.Stderr, "shudod: request expiry maintenance failed: %v\n", err)
			}
		case <-retentionTicker.C:
			s.runRetentionMaintenance("scheduled")
		}
	}
}

func (s *Service) runRetentionMaintenance(schedule string) {
	if err := s.Store.PruneUnapproved(time.Now().AddDate(0, 0, -s.Config.RetentionDays), s.Config.MaxRetainedUnapproved); err != nil {
		fmt.Fprintf(os.Stderr, "shudod: %s request retention maintenance failed: %v\n", schedule, err)
	}
}

func (s *Service) Cancel(ctx context.Context, input *shudov1.CancelRequest) (*shudov1.CancelResponse, error) {
	actor, err := requester(ctx)
	if err != nil {
		return nil, err
	}
	item, err := s.Store.Get(input.GetRequestId())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, status.Error(codes.NotFound, "request not found")
	}
	if actor.UID != 0 && actor.UID != item.Request.Requester.UID {
		return nil, status.Error(codes.PermissionDenied, "request belongs to another local user")
	}
	if item.Status != model.Created && item.Status != model.Waiting {
		return nil, status.Error(codes.FailedPrecondition, "request can no longer be cancelled")
	}
	if err := s.Store.Transition(input.GetRequestId(), model.Cancelled, item.Status); err != nil {
		return nil, err
	}
	return &shudov1.CancelResponse{Status: model.Cancelled}, nil
}

func (s *Service) execute(requestID string) {
	if _, loaded := s.executing.LoadOrStore(requestID, struct{}{}); loaded {
		return
	}
	defer s.executing.Delete(requestID)
	item, err := s.Store.Get(requestID)
	if err != nil || item == nil {
		return
	}
	expected := model.Approved
	now := time.Now()
	requestExpiry, err := time.Parse(time.RFC3339Nano, item.Request.ExpiresAt)
	if err != nil || !requestExpiry.After(now) {
		_ = s.Store.Transition(requestID, model.Expired, expected)
		return
	}
	recomputedHash, err := securejson.Hash(item.Request)
	if err != nil || !cryptoutil.Equal(recomputedHash, item.RequestHash) {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		_ = s.Store.RecordSecurityEvent("request.integrity-failed", requestID, item.RequestHash, "Persisted request hash mismatch before execution")
		return
	}
	approval, approvalErr := s.Store.ApprovalFor(requestID)
	if approvalErr != nil || approval == nil || approval.Decision != "approve" ||
		!cryptoutil.Equal(approval.RequestID, item.Request.RequestID) ||
		!cryptoutil.Equal(approval.RequestHash, item.RequestHash) {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		_ = s.Store.RecordSecurityEvent("approval.integrity-failed", requestID, item.RequestHash, "Local approval binding mismatch")
		return
	}
	currentPolicy, err := policy.Load(s.Config.PolicyPath)
	if err != nil {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		return
	}
	action := policy.Evaluate(currentPolicy, policy.Input{Executable: item.Request.Execution.Executable, Argv: item.Request.Execution.Argv, Cwd: item.Request.Execution.Cwd, UID: item.Request.Requester.UID})
	if action == policy.Deny || len(item.Request.Execution.Env) != 0 {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		return
	}
	verifiedDirectory, err := integrity.OpenVerifiedDirectory(item.Request.WorkingDirectoryMetadata)
	if err != nil {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		return
	}
	defer verifiedDirectory.Close()
	verifiedExecutable, err := integrity.OpenVerifiedExecutable(item.Request.ExecutableMetadata)
	if err != nil {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		return
	}
	defer verifiedExecutable.Close()
	var verifiedInterpreter *os.File
	interpreterPath := ""
	if item.Request.InterpreterMetadata != nil {
		verifiedInterpreter, err = integrity.OpenVerifiedExecutable(*item.Request.InterpreterMetadata)
		if err != nil {
			_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
			return
		}
		defer verifiedInterpreter.Close()
		interpreterPath = item.Request.InterpreterMetadata.Path
	}
	environment, err := integrity.SanitizeEnvironment(item.Request.Execution.Env, s.Config.AllowedEnvironment)
	if err != nil {
		_ = s.Store.Transition(requestID, model.PolicyRejected, expected)
		return
	}
	if err := s.Store.BeginExecution(requestID, expected); err != nil {
		return
	}
	argumentPresent, interpreterArgument := "0", ""
	if item.Request.InterpreterArgument != nil {
		argumentPresent, interpreterArgument = "1", *item.Request.InterpreterArgument
	}
	helperArguments := append([]string{"__exec-fds", item.Request.Execution.Executable, interpreterPath, argumentPresent, interpreterArgument}, item.Request.Execution.Argv...)
	cmd := s.newExecutionCommand(helperArguments...)
	cmd.Env = environment
	cmd.Stdin = nil
	cmd.ExtraFiles = []*os.File{verifiedExecutable, verifiedDirectory}
	if verifiedInterpreter != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, verifiedInterpreter)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		code := int32(127)
		_ = s.Store.FinishExecution(requestID, &code, "")
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		code := int32(127)
		_ = s.Store.FinishExecution(requestID, &code, "")
		return
	}
	if err := cmd.Start(); err != nil {
		code := int32(127)
		_ = s.Store.FinishExecution(requestID, &code, "")
		return
	}
	_ = verifiedExecutable.Close()
	var executionTimedOut atomic.Bool
	executionLimit := time.Duration(s.Config.MaxExecutionSeconds) * time.Second
	if untilRequestExpiry := time.Until(requestExpiry); untilRequestExpiry < executionLimit {
		executionLimit = untilRequestExpiry
	}
	executionTimer := time.AfterFunc(executionLimit, func() {
		executionTimedOut.Store(true)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	var sequence uint64
	var capture sync.Mutex
	truncated := false
	drain := func(stream string, reader interface{ Read([]byte) (int, error) }) {
		buffer := make([]byte, 32*1024)
		for {
			n, readErr := reader.Read(buffer)
			if n > 0 {
				capture.Lock()
				seq := sequence
				sequence++
				wasTruncated, _, _ := s.Store.AppendOutput(requestID, seq, stream, append([]byte(nil), buffer[:n]...), s.Config.Output.PersistedBytes)
				truncated = truncated || wasTruncated
				capture.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}
	var wait sync.WaitGroup
	wait.Add(2)
	go func() { defer wait.Done(); drain("stdout", stdout) }()
	go func() { defer wait.Done(); drain("stderr", stderr) }()
	waitErr := cmd.Wait()
	executionTimer.Stop()
	wait.Wait()
	var exitCode *int32
	signal := ""
	if cmd.ProcessState != nil {
		if statusValue, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			if statusValue.Exited() {
				value := int32(statusValue.ExitStatus())
				exitCode = &value
			}
			if statusValue.Signaled() {
				signal = statusValue.Signal().String()
			}
		}
	}
	if executionTimedOut.Load() {
		signal = "EXECUTION_TIMEOUT"
	}
	if exitCode == nil && waitErr == nil {
		value := int32(0)
		exitCode = &value
	}
	_ = s.Store.FinishExecution(requestID, exitCode, signal)
	_ = truncated
}

func (s *Service) newExecutionCommand(arguments ...string) *exec.Cmd {
	if s.commandFactory != nil {
		return s.commandFactory("/proc/self/exe", arguments...)
	}
	return exec.Command("/proc/self/exe", arguments...)
}

func (s *Service) RecoverApproved() {
	if err := s.Store.ExpireOutstanding(); err != nil {
		fmt.Fprintf(os.Stderr, "shudod: failed to expire requests during recovery: %v\n", err)
		return
	}
	if items, err := s.Store.Approved(); err == nil {
		for _, item := range items {
			go s.execute(item.Request.RequestID)
		}
	}
}

func (s *Service) acquireSubmission(uid uint32) error {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	times := s.submissionTimes[uid][:0]
	for _, submitted := range s.submissionTimes[uid] {
		if submitted.After(cutoff) {
			times = append(times, submitted)
		}
	}
	if len(times) >= s.Config.MaxSubmissionsPerMinute || s.submitting[uid] >= s.Config.MaxConcurrentPerUID || s.submittingTotal >= s.Config.MaxConcurrentTotal {
		s.submissionTimes[uid] = times
		return status.Error(codes.ResourceExhausted, "submission rate or concurrency limit reached")
	}
	s.submissionTimes[uid] = append(times, now)
	s.submitting[uid]++
	s.submittingTotal++
	return nil
}

func (s *Service) releaseSubmission(uid uint32) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	s.submitting[uid]--
	s.submittingTotal--
	if s.submitting[uid] == 0 {
		delete(s.submitting, uid)
	}
}

func (s *Service) acquireWatcher(uid uint32, requestID string) error {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.watchersByUID[uid] >= s.Config.MaxWatchersPerUID || s.watchersByRequest[requestID] >= s.Config.MaxWatchersPerRequest {
		return status.Error(codes.ResourceExhausted, "watcher limit reached")
	}
	s.watchersByUID[uid]++
	s.watchersByRequest[requestID]++
	return nil
}

func (s *Service) releaseWatcher(uid uint32, requestID string) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	s.watchersByUID[uid]--
	s.watchersByRequest[requestID]--
	if s.watchersByUID[uid] == 0 {
		delete(s.watchersByUID, uid)
	}
	if s.watchersByRequest[requestID] == 0 {
		delete(s.watchersByRequest, requestID)
	}
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func hostname() string {
	value, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return value
}

func command(executable string, argv []string) string {
	values := append([]string{executable}, argv...)
	for index, value := range values {
		values[index] = displayArgument(value)
	}
	return strings.Join(values, " ")
}

func displayArgument(value string) string {
	if value != "" && strings.IndexFunc(value, func(character rune) bool {
		return !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_@%+=:,./-", character))
	}) == -1 {
		return value
	}
	return strconv.QuoteToASCII(value)
}

func validateSubmit(input *shudov1.SubmitRequest) error {
	if input == nil {
		return fmt.Errorf("request is required")
	}
	if len(input.GetExecutable()) == 0 || len(input.GetExecutable()) > 4096 || strings.ContainsRune(input.GetExecutable(), '\x00') {
		return fmt.Errorf("invalid executable")
	}
	if len(input.GetCwd()) == 0 || len(input.GetCwd()) > 4096 || strings.ContainsRune(input.GetCwd(), '\x00') || !filepath.IsAbs(input.GetCwd()) {
		return fmt.Errorf("working directory must be a valid absolute path")
	}
	if len(input.GetReason()) > 4096 || strings.TrimSpace(input.GetReason()) == "" || strings.ContainsRune(input.GetReason(), '\x00') {
		return fmt.Errorf("a non-empty reason is required")
	}
	if input.GetTimeoutMs() < 1_000 || input.GetTimeoutMs() > 86_400_000 || len(input.GetArgv()) > 4096 {
		return fmt.Errorf("invalid arguments, environment, or timeout")
	}
	if len(input.GetEnv()) != 0 {
		return fmt.Errorf("environment overrides are not supported")
	}
	total := 0
	for _, value := range input.GetArgv() {
		total += len(value)
		if len(value) > 131_072 || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("invalid command argument")
		}
	}
	if total > 384*1024 {
		return fmt.Errorf("request payload is too large")
	}
	return nil
}

func approvalActor(approval model.Approval) string {
	if approval.ApprovedBy.DisplayName != nil && *approval.ApprovedBy.DisplayName != "" {
		return *approval.ApprovedBy.DisplayName
	}
	return approval.ApprovedBy.Subject
}
