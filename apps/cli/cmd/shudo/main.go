//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var socketPath = localSocketPath()

type options struct {
	reason  string
	timeout time.Duration
	detach  bool
	json    bool
	verbose bool
	command []string
}

type adminOptions struct {
	operation   string
	requestID   string
	reason      string
	json        bool
	verbose     bool
	confirmHash string
}

func main() {
	code, err := run()
	if err != nil {
		if message := friendly(err); message != "" {
			fmt.Fprintf(os.Stderr, "shudo: %s\n", message)
		}
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func localSocketPath() string {
	if value := os.Getenv("SHUDO_SOCKET_PATH"); filepath.IsAbs(value) && !strings.ContainsRune(value, '\x00') {
		return value
	}
	return "/run/shudo/shudo.sock"
}

func run() (int, error) {
	if admin, ok, err := parseAdmin(os.Args[1:]); ok || err != nil {
		if err != nil {
			return 2, err
		}
		return runAdmin(admin)
	}
	return runCommand(os.Args[1:])
}

func runCommand(arguments []string) (int, error) {
	options, err := parse(arguments)
	if err != nil {
		return 2, err
	}
	if strings.TrimSpace(options.reason) == "" {
		options.reason, err = prompt("Reason: ")
		if err != nil {
			return 2, err
		}
	}
	deadline := time.Now().Add(options.timeout)
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	connection, client, err := dialLocal()
	if err != nil {
		return 1, err
	}
	submitDeadline := deadline
	if maximum := time.Now().Add(15 * time.Second); maximum.Before(submitDeadline) {
		submitDeadline = maximum
	}
	ctx, cancel := context.WithDeadline(context.Background(), submitDeadline)
	response, err := client.Submit(ctx, &shudov1.SubmitRequest{
		Executable: options.command[0], Argv: options.command[1:], Cwd: cwd,
		Reason: options.reason, TimeoutMs: options.timeout.Milliseconds(),
	})
	cancel()
	_ = connection.Close()
	if err != nil {
		return 1, err
	}
	if options.json {
		emitJSON(map[string]any{"type": "submitted", "requestId": response.RequestId, "requestHash": response.RequestHash, "status": response.Status, "hostname": response.Hostname, "command": response.Command})
	}
	if options.detach {
		if !options.json {
			fmt.Println(response.RequestId)
		}
		return 0, nil
	}
	if options.verbose && !options.json {
		fmt.Fprintf(os.Stderr, "Request %s: %s\n", response.RequestId, response.Command)
	}
	watchContext, cancelWatch := context.WithDeadline(context.Background(), deadline)
	defer cancelWatch()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	interrupted := make(chan struct{})
	go func() {
		select {
		case <-signals:
			close(interrupted)
			cancelContext, cancelCall := context.WithTimeout(context.Background(), 2*time.Second)
			cancelRequest(cancelContext, response.RequestId)
			cancelCall()
			cancelWatch()
		case <-watchContext.Done():
		}
	}()
	nextSequence := uint64(0)
	retryDelay := 50 * time.Millisecond
	for {
		connection, client, err = dialLocal()
		if err == nil {
			var stream shudov1.LocalBroker_WatchClient
			stream, err = client.Watch(watchContext, &shudov1.WatchRequest{RequestId: response.RequestId, AfterSequence: nextSequence})
			if err == nil {
				for {
					event, receiveErr := stream.Recv()
					if receiveErr != nil {
						err = receiveErr
						break
					}
					retryDelay = 50 * time.Millisecond
					if event.Type == "output" {
						if event.Sequence < nextSequence {
							continue
						}
						nextSequence = event.Sequence + 1
					}
					if options.json {
						payload := map[string]any{"type": event.Type, "requestId": event.RequestId, "status": event.Status}
						if len(event.Data) > 0 {
							payload["stream"] = event.Stream
							payload["dataBase64"] = base64.RawURLEncoding.EncodeToString(event.Data)
						}
						if event.ApprovedBy != "" {
							payload["approvedBy"] = event.ApprovedBy
						}
						if event.Decision != "" {
							payload["decision"] = event.Decision
						}
						if event.HasExitCode {
							payload["exitCode"] = event.ExitCode
						}
						if event.Signal != "" {
							payload["signal"] = event.Signal
						}
						if event.Truncated {
							payload["truncated"] = true
						}
						emitJSON(payload)
					} else if event.Type == "output" {
						if event.Stream == "stderr" {
							_, _ = os.Stderr.Write(event.Data)
						} else {
							_, _ = os.Stdout.Write(event.Data)
						}
					}
					if event.Type == "finished" {
						_ = connection.Close()
						if options.verbose && !options.json && event.ApprovedBy != "" {
							fmt.Fprintf(os.Stderr, "Approved by %s.\n", event.ApprovedBy)
						}
						switch event.Status {
						case "SUCCEEDED":
							return 0, nil
						case "FAILED":
							if event.HasExitCode {
								return int(event.ExitCode), nil
							}
							return 1, nil
						case "DENIED":
							return 1, errors.New("request denied")
						case "POLICY_REJECTED":
							return 1, errors.New("request rejected by local policy")
						case "EXPIRED":
							return 1, errors.New("request timed out")
						case "CANCELLED":
							return 130, errors.New("request cancelled")
						default:
							return 1, fmt.Errorf("request ended in %s", event.Status)
						}
					}
				}
			}
		}
		if connection != nil {
			_ = connection.Close()
		}
		if watchContext.Err() != nil {
			return watchContextResult(interrupted)
		}
		if !retryableWatchError(err) {
			return 1, err
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-watchContext.Done():
			timer.Stop()
			return watchContextResult(interrupted)
		case <-timer.C:
		}
		if retryDelay < time.Second {
			retryDelay *= 2
		}
	}
}

func runAdmin(options adminOptions) (int, error) {
	if err := requireRootReview(os.Geteuid()); err != nil {
		return 1, err
	}
	connection, client, err := dialLocal()
	if err != nil {
		return 1, err
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch options.operation {
	case "pending", "history":
		response, err := client.ListRequests(ctx, &shudov1.ListRequestsRequest{IncludeHistory: options.operation == "history"})
		if err != nil {
			return 1, err
		}
		if options.json {
			emitJSON(recordsJSON(response.Requests))
			return 0, nil
		}
		if len(response.Requests) == 0 {
			fmt.Println("No requests.")
			return 0, nil
		}
		for _, record := range response.Requests {
			printSummary(record)
		}
	case "show":
		requestID := options.requestID
		if len(requestID) != 36 {
			requestID, err = selectRequest(ctx, client, requestID, true, "View")
			if err != nil {
				return 1, err
			}
		}
		record, err := inspectRequest(client, requestID)
		if err != nil {
			return 1, err
		}
		if options.json {
			emitJSON(recordJSON(record))
			return 0, nil
		}
		printRecord(record, options.verbose)
	case "approve", "deny":
		action := "Approve"
		if options.operation == "deny" {
			action = "Deny"
		}
		requestID, err := selectRequest(ctx, client, options.requestID, false, action)
		if err != nil {
			return 1, err
		}
		requestHash := ""
		if options.operation == "approve" {
			record, inspectErr := inspectRequest(client, requestID)
			if inspectErr != nil {
				return 1, inspectErr
			}
			if options.confirmHash != "" {
				if options.confirmHash != record.RequestHash {
					return 1, errors.New("--confirm-hash does not match the current request")
				}
			} else {
				if options.json {
					return 2, errors.New("non-interactive approval requires --confirm-hash with the full inspected hash")
				}
				if err := confirmApproval(record); err != nil {
					return 1, err
				}
			}
			requestHash = record.RequestHash
		}
		request := &shudov1.DecisionRequest{RequestId: requestID, RequestHash: requestHash, Reason: options.reason}
		var response *shudov1.DecisionResponse
		decisionCtx, decisionCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer decisionCancel()
		if options.operation == "approve" {
			response, err = client.Approve(decisionCtx, request)
		} else {
			response, err = client.Deny(decisionCtx, request)
		}
		if err != nil && ambiguousDecisionError(err) {
			response, err = reconcileDecision(client, request, options.operation, err)
			if err == nil && !options.json {
				fmt.Fprintln(os.Stderr, "Decision confirmed from authoritative server state after an ambiguous RPC result.")
			}
		}
		if err != nil {
			return 1, err
		}
		if options.json {
			emitJSON(map[string]any{"requestId": response.RequestId, "approvalId": response.ApprovalId, "status": response.Status, "decidedBy": response.DecidedBy})
			return 0, nil
		}
		verb := "Approved"
		if options.operation == "deny" {
			verb = "Denied"
		}
		fmt.Printf("%s %s.\n", verb, response.RequestId)
	}
	return 0, nil
}

func ambiguousDecisionError(err error) bool {
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unknown, codes.Internal, codes.Unavailable:
		return true
	default:
		return false
	}
}

func inspectRequest(client shudov1.LocalBrokerClient, requestID string) (*shudov1.RequestRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return client.InspectRequest(ctx, &shudov1.InspectRequestRequest{RequestId: requestID})
}

func reconcileDecision(client shudov1.LocalBrokerClient, request *shudov1.DecisionRequest, decision string, decisionErr error) (*shudov1.DecisionResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	record, err := client.InspectRequest(ctx, &shudov1.InspectRequestRequest{RequestId: request.RequestId})
	if err != nil {
		return nil, fmt.Errorf("decision outcome is uncertain after %v; authoritative inspection failed: %w", decisionErr, err)
	}
	response, reconcileErr := decisionResponseFromRecord(record, request, decision)
	if reconcileErr != nil {
		return nil, fmt.Errorf("decision RPC returned %v; %w", decisionErr, reconcileErr)
	}
	return response, nil
}

func decisionResponseFromRecord(record *shudov1.RequestRecord, request *shudov1.DecisionRequest, decision string) (*shudov1.DecisionResponse, error) {
	if record == nil || record.RequestId != request.RequestId {
		return nil, errors.New("authoritative inspection returned the wrong request")
	}
	if record.Decision == "" {
		if record.Status == "WAITING_APPROVAL" {
			return nil, errors.New("the decision was not committed; request remains pending and may be retried")
		}
		return nil, fmt.Errorf("request is %s without a stored decision", record.Status)
	}
	if record.Decision != decision {
		return nil, fmt.Errorf("request has a conflicting %s decision", record.Decision)
	}
	if record.ApprovalId == "" {
		return nil, errors.New("stored decision is missing its approval ID")
	}
	if decision == "approve" && (record.RequestHash != request.RequestHash || request.RequestHash == "") {
		return nil, errors.New("stored approval does not match the confirmed request hash")
	}
	next := "DENIED"
	if decision == "approve" {
		next = "APPROVED"
	}
	return &shudov1.DecisionResponse{
		RequestId: record.RequestId, ApprovalId: record.ApprovalId,
		Status: next, DecidedBy: record.DecidedBy,
	}, nil
}

func requireRootReview(euid int) error {
	if euid != 0 {
		return errors.New("review commands require this process to already be running as root")
	}
	return nil
}

func parseAdmin(arguments []string) (adminOptions, bool, error) {
	var result adminOptions
	if len(arguments) == 0 {
		return result, false, nil
	}
	operations := map[string]string{"--pending": "pending", "--requests": "history", "--history": "history", "--show": "show", "--approve": "approve", "--deny": "deny"}
	operation, ok := operations[arguments[0]]
	if !ok {
		return result, false, nil
	}
	result.operation = operation
	arguments = arguments[1:]
	if (operation == "show" || operation == "approve" || operation == "deny") && len(arguments) > 0 && !strings.HasPrefix(arguments[0], "-") {
		result.requestID = arguments[0]
		arguments = arguments[1:]
	}
	for len(arguments) > 0 {
		switch arguments[0] {
		case "--json":
			result.json = true
			arguments = arguments[1:]
		case "--verbose":
			result.verbose = true
			arguments = arguments[1:]
		case "--reason":
			if len(arguments) < 2 {
				return result, true, errors.New("--reason needs a value")
			}
			result.reason = arguments[1]
			arguments = arguments[2:]
		case "--confirm-hash":
			if len(arguments) < 2 {
				return result, true, errors.New("--confirm-hash needs a value")
			}
			result.confirmHash = arguments[1]
			arguments = arguments[2:]
		default:
			return result, true, fmt.Errorf("unexpected review option %s", arguments[0])
		}
	}
	if result.reason != "" && operation != "approve" && operation != "deny" {
		return result, true, errors.New("--reason is valid only with --approve or --deny")
	}
	if result.confirmHash != "" && operation != "approve" {
		return result, true, errors.New("--confirm-hash is valid only with --approve")
	}
	return result, true, nil
}

func printSummary(record *shudov1.RequestRecord) {
	requester := record.RequesterUsername
	if requester == "" {
		requester = fmt.Sprintf("uid:%d", record.RequesterUid)
	}
	fmt.Printf("%s  %s  %s\n  %s\n  Reason: %s\n", shortID(record.RequestId), terminalText(record.Status), terminalText(requester), terminalText(record.Command), terminalText(record.Reason))
}

func selectRequest(ctx context.Context, client shudov1.LocalBrokerClient, selector string, history bool, action string) (string, error) {
	response, err := client.ListRequests(ctx, &shudov1.ListRequestsRequest{IncludeHistory: history})
	if err != nil {
		return "", err
	}
	if len(response.Requests) == 0 {
		if history {
			return "", errors.New("no recent requests")
		}
		return "", errors.New("no pending requests")
	}
	if selector == "" {
		return pickRequest(response.Requests, action)
	}
	if len(selector) < 4 {
		return "", errors.New("request ID prefix must contain at least 4 characters")
	}
	var match *shudov1.RequestRecord
	for _, record := range response.Requests {
		if strings.HasPrefix(strings.ToLower(record.RequestId), strings.ToLower(selector)) {
			if match != nil {
				return "", fmt.Errorf("request ID prefix %q is ambiguous", selector)
			}
			match = record
		}
	}
	if match == nil {
		kind := "pending"
		if history {
			kind = "recent"
		}
		return "", fmt.Errorf("no matching %s request", kind)
	}
	return match.RequestId, nil
}

func pickRequest(records []*shudov1.RequestRecord, action string) (string, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("request ID is required when no interactive terminal is available")
	}
	defer terminal.Close()
	for index, record := range records {
		requester := record.RequesterUsername
		if requester == "" {
			requester = fmt.Sprintf("uid:%d", record.RequesterUid)
		}
		fmt.Fprintf(terminal, "[%d] %s  %s\n    %s\n    Reason: %s\n", index+1, shortID(record.RequestId), terminalText(requester), terminalText(record.Command), terminalText(record.Reason))
	}
	fmt.Fprintf(terminal, "%s request [1-%d, q]: ", action, len(records))
	line, readErr := bufio.NewReader(io.LimitReader(terminal, 32)).ReadString('\n')
	if readErr != nil && len(line) == 0 {
		return "", readErr
	}
	choice := strings.TrimSpace(line)
	if choice == "q" || choice == "Q" {
		return "", errors.New("selection cancelled")
	}
	index, parseErr := strconv.Atoi(choice)
	if parseErr != nil || index < 1 || index > len(records) {
		return "", errors.New("invalid request selection")
	}
	return records[index-1].RequestId, nil
}

func shortID(requestID string) string {
	if len(requestID) <= 8 {
		return terminalText(requestID)
	}
	return terminalText(requestID[:8])
}

func printRecord(record *shudov1.RequestRecord, verbose bool) {
	printRecordTo(os.Stdout, record, verbose)
}

func printRecordTo(writer io.Writer, record *shudov1.RequestRecord, verbose bool) {
	requester := record.RequesterUsername
	if requester == "" {
		requester = fmt.Sprintf("uid:%d", record.RequesterUid)
	}
	fmt.Fprintf(writer, "Request:   %s\nStatus:    %s\nRequester: %s\nCommand:   %s\nReason:    %s\nDirectory: %s\nCreated:   %s\nExpires:   %s\n", terminalText(record.RequestId), terminalText(record.Status), terminalText(requester), terminalText(record.Command), terminalText(record.Reason), terminalText(record.Cwd), terminalText(record.CreatedAt), terminalText(record.ExpiresAt))
	if len(record.Env) > 0 {
		fmt.Fprintln(writer, "Environment:")
		keys := make([]string, 0, len(record.Env))
		for key := range record.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(writer, "  %s=%s\n", terminalText(key), terminalText(record.Env[key]))
		}
	}
	if len(record.Warnings) > 0 {
		fmt.Fprintf(writer, "Warnings:  %s\n", terminalText(strings.Join(record.Warnings, "; ")))
	}
	if record.DecidedBy != "" {
		label := record.Decision
		if label == "" {
			label = "recorded"
		}
		fmt.Fprintf(writer, "Decision:  %s by %s", terminalText(label), terminalText(record.DecidedBy))
		if record.DecisionReason != "" {
			fmt.Fprintf(writer, " — %s", terminalText(record.DecisionReason))
		}
		fmt.Fprintln(writer)
	}
	if verbose {
		fmt.Fprintf(writer, "Executable: %s\n", terminalText(record.Executable))
		for index, value := range record.Argv {
			fmt.Fprintf(writer, "Arg[%d]:    %s\n", index, strconv.QuoteToASCII(value))
		}
		fmt.Fprintf(writer, "UID/GID:   %d/%d\nPolicy:    %s\nHash:      %s\n", record.RequesterUid, record.RequesterGid, record.PolicyResult, record.RequestHash)
		if record.ApprovalId != "" {
			fmt.Fprintf(writer, "Approval:  %s\n", terminalText(record.ApprovalId))
		}
	}
}

func confirmApproval(record *shudov1.RequestRecord) error {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("interactive approval requires /dev/tty; use --confirm-hash after inspecting the request")
	}
	defer terminal.Close()
	printRecordTo(terminal, record, true)
	fmt.Fprint(terminal, "Approve this exact request [y/N]: ")
	line, readErr := bufio.NewReader(io.LimitReader(terminal, 8)).ReadString('\n')
	if readErr != nil && len(line) == 0 {
		return readErr
	}
	if choice := strings.TrimSpace(line); choice != "y" && choice != "Y" {
		return errors.New("approval cancelled")
	}
	return nil
}

func recordJSON(record *shudov1.RequestRecord) map[string]any {
	return map[string]any{
		"requestId": record.RequestId, "requestHash": record.RequestHash, "status": record.Status,
		"requester":  map[string]any{"uid": record.RequesterUid, "gid": record.RequesterGid, "username": record.RequesterUsername, "group": record.RequesterGroup},
		"executable": record.Executable, "argv": record.Argv, "command": record.Command, "cwd": record.Cwd, "env": record.Env,
		"reason": record.Reason, "createdAt": record.CreatedAt, "expiresAt": record.ExpiresAt, "policyResult": record.PolicyResult,
		"risk":     map[string]any{"shell": record.Shell, "interpreter": record.Interpreter, "script": record.Script, "warnings": record.Warnings},
		"decision": record.Decision, "approvalId": record.ApprovalId,
		"decidedBy": record.DecidedBy, "decisionReason": record.DecisionReason,
	}
}

func recordsJSON(records []*shudov1.RequestRecord) []map[string]any {
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		result = append(result, recordJSON(record))
	}
	return result
}

func dialLocal() (*grpc.ClientConn, shudov1.LocalBrokerClient, error) {
	connection, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(2*1024*1024)))
	if err != nil {
		return nil, nil, err
	}
	return connection, shudov1.NewLocalBrokerClient(connection), nil
}

func cancelRequest(ctx context.Context, requestID string) {
	connection, client, err := dialLocal()
	if err != nil {
		return
	}
	defer connection.Close()
	_, _ = client.Cancel(ctx, &shudov1.CancelRequest{RequestId: requestID})
}

func retryableWatchError(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	switch status.Code(err) {
	case codes.Canceled, codes.Unknown, codes.Internal, codes.Unavailable:
		return true
	default:
		return false
	}
}

func watchContextResult(interrupted <-chan struct{}) (int, error) {
	select {
	case <-interrupted:
		return 130, nil
	default:
		return 1, errors.New("request timed out")
	}
}

func parse(arguments []string) (options, error) {
	result := options{timeout: 5 * time.Minute}
	if len(arguments) > 0 && arguments[0] == "exec" {
		arguments = arguments[1:]
	}
	for len(arguments) > 0 {
		value := arguments[0]
		if value == "--" {
			arguments = arguments[1:]
			break
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			break
		}
		switch value {
		case "--reason":
			if len(arguments) < 2 {
				return result, errors.New("--reason needs a value")
			}
			result.reason = arguments[1]
			arguments = arguments[2:]
		case "--timeout":
			if len(arguments) < 2 {
				return result, errors.New("--timeout needs a duration")
			}
			parsed, err := time.ParseDuration(arguments[1])
			if err != nil || parsed < time.Second || parsed > 24*time.Hour {
				return result, errors.New("--timeout must be between 1s and 24h")
			}
			result.timeout = parsed
			arguments = arguments[2:]
		case "--detach":
			result.detach = true
			arguments = arguments[1:]
		case "--json":
			result.json = true
			arguments = arguments[1:]
		case "--verbose":
			result.verbose = true
			arguments = arguments[1:]
		case "--env":
			return result, errors.New("--env is not supported because request data is retained; use a reviewed command-specific secret mechanism")
		case "-h", "--help":
			return result, errors.New(usage())
		default:
			return result, fmt.Errorf("unknown shudo option %s (use -- before command options)", value)
		}
	}
	if len(arguments) == 0 {
		return result, errors.New("no command specified\n" + usage())
	}
	result.command = arguments
	return result, nil
}

func prompt(label string) (string, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("a reason is required when no interactive terminal is available")
	}
	defer terminal.Close()
	_, _ = fmt.Fprint(terminal, label)
	line, err := bufio.NewReader(io.LimitReader(terminal, 4097)).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", errors.New("reason cannot be empty")
	}
	if len(line) > 4096 {
		return "", errors.New("reason is too long")
	}
	return line, nil
}

func usage() string {
	return "usage: shudo [--reason TEXT] [--timeout 5m] [--detach] [--json|--verbose] [--] COMMAND [ARG ...]\n" +
		"       shudo --pending | --requests | --show [ID-PREFIX] | --approve [ID-PREFIX] | --deny [ID-PREFIX]"
}

func terminalText(value string) string {
	if strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) == -1 {
		return value
	}
	return strconv.QuoteToASCII(value)
}

func emitJSON(value any) { raw, _ := json.Marshal(value); fmt.Println(string(raw)) }
func friendly(err error) string {
	if current, ok := status.FromError(err); ok {
		return strings.TrimSpace(current.Message())
	}
	return strings.TrimSpace(err.Error())
}
