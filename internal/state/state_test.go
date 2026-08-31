package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shudo.local/shudo/internal/model"
)

func testRequest(id string, uid uint32, expires time.Time) model.ExecutionRequest {
	return model.ExecutionRequest{
		Version: 1, RequestID: id, Requester: model.Requester{UID: uid, GID: uid},
		Execution: model.Execution{Executable: "/usr/bin/id", Argv: []string{}, Cwd: "/"},
		Reason:    "test", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano), Nonce: "request-nonce",
	}
}

func testApproval(request model.ExecutionRequest, hash, id string) model.Approval {
	return model.Approval{
		Version: 1, ApprovalID: id, RequestID: request.RequestID, RequestHash: hash,
		Decision: "approve", ApprovedBy: model.ApprovedBy{Subject: "uid:0"},
		ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano), Reason: "reviewed locally",
	}
}

func TestStateMachineAndApprovalSingleUse(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("request-a", 1000, time.Now().Add(time.Minute))
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	approval := testApproval(request, hash, "approval-a")
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptApproval(approval); err == nil {
		t.Fatal("approval replay was accepted")
	}
	if err := store.BeginExecution(request.RequestID, model.Approved); err != nil {
		t.Fatal(err)
	}
	code := int32(0)
	if err := store.FinishExecution(request.RequestID, &code, ""); err != nil {
		t.Fatal(err)
	}
	item, err := store.Get(request.RequestID)
	if err != nil || item.Status != model.Succeeded {
		t.Fatalf("unexpected final state: %#v %v", item, err)
	}
	if err := store.Transition(request.RequestID, model.Executing, model.Succeeded); err == nil {
		t.Fatal("terminal transition accepted")
	}
}

func TestCanceledApprovalContextDoesNotCommit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("cancelled-decision", 1000, time.Now().Add(time.Minute))
	const hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := store.Create(request, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.AcceptApprovalContext(ctx, testApproval(request, hash, "cancelled-approval")); err == nil {
		t.Fatal("approval committed after its RPC context was cancelled")
	}
	approval, err := store.ApprovalFor(request.RequestID)
	if err != nil || approval != nil {
		t.Fatalf("cancelled approval was persisted: %#v %v", approval, err)
	}
	item, err := store.Get(request.RequestID)
	if err != nil || item.Status != model.Waiting {
		t.Fatalf("cancelled decision changed request state: %#v %v", item, err)
	}
}

func TestOutstandingRequestExpires(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("expired-request", 1000, time.Now().Add(-time.Second))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireOutstanding(); err != nil {
		t.Fatal(err)
	}
	item, err := store.Get(request.RequestID)
	if err != nil || item == nil || item.Status != model.Expired {
		t.Fatalf("request was not expired: %#v %v", item, err)
	}
}

func TestApprovedRequestExpiresBeforeRecovery(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("expired-approved", 1000, time.Now().Add(-time.Second))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptApproval(testApproval(request, "hash", "expired-approval")); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireOutstanding(); err != nil {
		t.Fatal(err)
	}
	item, err := store.Get(request.RequestID)
	if err != nil || item == nil || item.Status != model.Expired {
		t.Fatalf("approved request was not expired: %#v %v", item, err)
	}
}

func TestBeginExecutionRequiresUnconsumedApproval(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("already-consumed", 1000, time.Now().Add(time.Minute))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptApproval(testApproval(request, "hash", "consumed-approval")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE approvals SET consumed_at=? WHERE request_id=?", now(), request.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(request.RequestID, model.Approved); err == nil {
		t.Fatal("execution began with a consumed approval")
	}
	item, _ := store.Get(request.RequestID)
	if item == nil || item.Status != model.Approved {
		t.Fatalf("transaction was not rolled back: %#v", item)
	}
}

func TestOutstandingCountsArePerRequester(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index, uid := range []uint32{1000, 1000, 1001} {
		request := testRequest(fmt.Sprintf("request-%d", index), uid, time.Now().Add(time.Minute))
		if err := store.Create(request, fmt.Sprintf("hash-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	perUID, total, err := store.OutstandingCounts(1000)
	if err != nil {
		t.Fatal(err)
	}
	if perUID != 2 || total != 3 {
		t.Fatalf("got per-UID=%d total=%d, want 2 and 3", perUID, total)
	}
}

func TestLocalOnlyMigrationRejectsOldRemotePending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("old-remote-request", 1000, time.Now().Add(time.Minute))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Queued, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DELETE FROM server_state WHERE key='local_only_v2'"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	item, err := store.Get(request.RequestID)
	if err != nil || item == nil || item.Status != model.PolicyRejected {
		t.Fatalf("legacy pending survived: %#v %v", item, err)
	}
}

func TestLocalOnlyMigrationDropsLegacyHostColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-host.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TABLE requests (
 request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, request_json TEXT NOT NULL,
 status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 output_bytes INTEGER NOT NULL DEFAULT 0, output_truncated INTEGER NOT NULL DEFAULT 0,
 host_id TEXT
) STRICT;
CREATE TABLE server_state (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name='host_id'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy host column survived migration: %d %v", count, err)
	}
}

func TestLocalOnlyMigrationErrorsFailClosed(t *testing.T) {
	newStore := func(t *testing.T) *Store {
		t.Helper()
		store, err := Open(filepath.Join(t.TempDir(), "migration-error.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if _, err := store.db.Exec("DELETE FROM server_state WHERE key='local_only_v2'"); err != nil {
			t.Fatal(err)
		}
		return store
	}
	t.Run("update", func(t *testing.T) {
		store := newStore(t)
		request := testRequest("pending", 1000, time.Now().Add(time.Hour))
		if err := store.Create(request, "hash"); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("CREATE TRIGGER fail_migration_update BEFORE UPDATE ON requests BEGIN SELECT RAISE(ABORT,'blocked'); END"); err != nil {
			t.Fatal(err)
		}
		if err := store.migrateLocalOnly(); err == nil {
			t.Fatal("failed migration update was accepted")
		}
	})
	t.Run("outbound view", func(t *testing.T) {
		store := newStore(t)
		if _, err := store.db.Exec("CREATE VIEW outbound_events AS SELECT 1"); err != nil {
			t.Fatal(err)
		}
		if err := store.migrateLocalOnly(); err == nil {
			t.Fatal("failed outbound drop was accepted")
		}
	})
	t.Run("nonce view", func(t *testing.T) {
		store := newStore(t)
		if _, err := store.db.Exec("CREATE VIEW used_nonces AS SELECT 1"); err != nil {
			t.Fatal(err)
		}
		if err := store.migrateLocalOnly(); err == nil {
			t.Fatal("failed nonce drop was accepted")
		}
	})
	t.Run("quarantine delete", func(t *testing.T) {
		store := newStore(t)
		if _, err := store.db.Exec("INSERT INTO server_state(key,value) VALUES('approval_channel_quarantine','x')"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("CREATE TRIGGER fail_quarantine_delete BEFORE DELETE ON server_state WHEN OLD.key='approval_channel_quarantine' BEGIN SELECT RAISE(ABORT,'blocked'); END"); err != nil {
			t.Fatal(err)
		}
		if err := store.migrateLocalOnly(); err == nil {
			t.Fatal("failed quarantine delete was accepted")
		}
	})
	t.Run("marker insert", func(t *testing.T) {
		store := newStore(t)
		if _, err := store.db.Exec("CREATE TRIGGER fail_marker_insert BEFORE INSERT ON server_state BEGIN SELECT RAISE(ABORT,'blocked'); END"); err != nil {
			t.Fatal(err)
		}
		if err := store.migrateLocalOnly(); err == nil {
			t.Fatal("failed marker insert was accepted")
		}
	})
	t.Run("security event", func(t *testing.T) {
		store := newStore(t)
		if _, err := store.db.Exec("CREATE TRIGGER fail_migration_event BEFORE INSERT ON security_events BEGIN SELECT RAISE(ABORT,'blocked'); END"); err != nil {
			t.Fatal(err)
		}
		if err := store.migrateLocalOnly(); err == nil {
			t.Fatal("failed migration audit was accepted")
		}
	})
	closed := newStore(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closed.migrateLocalOnly(); err == nil {
		t.Fatal("migration on closed state succeeded")
	}
}

func TestImmutableRecordsAreDatabaseEnforced(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("immutable-request", 1000, time.Now().Add(time.Minute))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE requests SET request_hash='tampered' WHERE request_id=?", request.RequestID); err == nil {
		t.Fatal("database allowed an immutable request field to change")
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptApproval(testApproval(request, "hash", "immutable-approval")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DELETE FROM approvals WHERE request_id=?", request.RequestID); err == nil {
		t.Fatal("database allowed an approval to be deleted")
	}
}

func TestQueriesExecutionOutputAndAudit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	createWaiting := func(id string, uid uint32) model.ExecutionRequest {
		t.Helper()
		request := testRequest(id, uid, time.Now().Add(time.Hour))
		if err := store.Create(request, "hash-"+id); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(id, model.Waiting, model.Created); err != nil {
			t.Fatal(err)
		}
		return request
	}
	first := createWaiting("query-a", 1000)
	_ = createWaiting("query-b", 1001)

	pending, err := store.Pending()
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending mismatch: %#v %v", pending, err)
	}
	scoped, err := store.RecentPending(10, 1000, false)
	if err != nil || len(scoped) != 1 || scoped[0].Request.RequestID != first.RequestID {
		t.Fatalf("scoped pending mismatch: %#v %v", scoped, err)
	}
	allPending, err := store.RecentPending(10, 0, true)
	if err != nil || len(allPending) != 2 {
		t.Fatalf("all pending mismatch: %#v %v", allPending, err)
	}
	if _, err := store.Recent(0, 0, true); err == nil {
		t.Fatal("invalid recent limit accepted")
	}
	if _, err := store.recent(10, 0, true); err == nil {
		t.Fatal("empty status query accepted")
	}

	approval := testApproval(first, "hash-query-a", "approval-query-a")
	if err := store.AcceptApproval(approval); err != nil {
		t.Fatal(err)
	}
	storedApproval, err := store.ApprovalFor(first.RequestID)
	if err != nil || storedApproval == nil || storedApproval.ApprovalID != approval.ApprovalID {
		t.Fatalf("approval mismatch: %#v %v", storedApproval, err)
	}
	if missing, err := store.ApprovalFor("missing"); err != nil || missing != nil {
		t.Fatalf("missing approval mismatch: %#v %v", missing, err)
	}
	approved, err := store.Approved()
	if err != nil || len(approved) != 1 {
		t.Fatalf("approved query mismatch: %#v %v", approved, err)
	}
	if err := store.BeginExecution(first.RequestID, model.Approved); err != nil {
		t.Fatal(err)
	}
	truncated, stored, err := store.AppendOutput(first.RequestID, 0, "stdout", []byte("abcdef"), 5)
	if err != nil || !truncated || string(stored) != "abcde" {
		t.Fatalf("output cap failed: %v %q %v", truncated, stored, err)
	}
	truncated, stored, err = store.AppendOutput(first.RequestID, 1, "stderr", []byte("ignored"), 5)
	if err != nil || !truncated || stored != nil {
		t.Fatalf("truncated output was retained: %v %q %v", truncated, stored, err)
	}
	chunks, err := store.Output(first.RequestID)
	if err != nil || len(chunks) != 1 || chunks[0].Sequence != 0 || chunks[0].Stream != "stdout" || string(chunks[0].Data) != "abcde" {
		t.Fatalf("output mismatch: %#v %v", chunks, err)
	}
	code := int32(7)
	if err := store.FinishExecution(first.RequestID, &code, "TERM"); err != nil {
		t.Fatal(err)
	}
	execution, err := store.Execution(first.RequestID)
	if err != nil || execution == nil || execution.ExitCode == nil || *execution.ExitCode != 7 || execution.Signal != "TERM" || execution.FinishedAt == "" {
		t.Fatalf("execution mismatch: %#v %v", execution, err)
	}
	if missing, err := store.Execution("missing"); err != nil || missing != nil {
		t.Fatalf("missing execution mismatch: %#v %v", missing, err)
	}
	executed, err := store.Executed()
	if err != nil || len(executed) != 1 || executed[0].Status != model.Failed {
		t.Fatalf("executed query mismatch: %#v %v", executed, err)
	}

	if err := store.Transition("query-b", model.Cancelled, model.Waiting); err != nil {
		t.Fatal(err)
	}
	cancelled, err := store.Cancelled()
	if err != nil || len(cancelled) != 1 {
		t.Fatalf("cancelled query mismatch: %#v %v", cancelled, err)
	}
	all, err := store.All()
	if err != nil || len(all) != 2 {
		t.Fatalf("all query mismatch: %#v %v", all, err)
	}
	recent, err := store.Recent(1, 0, true)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent query mismatch: %#v %v", recent, err)
	}

	detail := strings.Repeat("x", 600)
	if err := store.RecordSecurityEvent("test.event", "", "", detail); err != nil {
		t.Fatal(err)
	}
	var length int
	if err := store.db.QueryRow("SELECT length(detail) FROM security_events WHERE type='test.event'").Scan(&length); err != nil || length != 512 {
		t.Fatalf("audit detail was not bounded: %d %v", length, err)
	}
	if boolInt(true) != 1 || boolInt(false) != 0 || nullable("") != nil || nullable("x") != "x" {
		t.Fatal("database helper mismatch")
	}
}

func TestStateErrorPathsAndRestartRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("restart", 1000, time.Now().Add(time.Hour))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition("missing", model.Waiting, model.Created); err == nil {
		t.Fatal("unknown transition accepted")
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Approved); err == nil {
		t.Fatal("wrong expected state accepted")
	}
	if err := store.Transition(request.RequestID, model.Succeeded, model.Created); err == nil {
		t.Fatal("invalid transition accepted")
	}
	if err := store.BeginExecution(request.RequestID, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	item, err := store.Get(request.RequestID)
	if err != nil || item.Status != model.Failed {
		t.Fatalf("interrupted execution was not failed: %#v %v", item, err)
	}
	execution, err := store.Execution(request.RequestID)
	if err != nil || execution.Signal != "DAEMON_RESTART" || execution.FinishedAt == "" {
		t.Fatalf("restart execution mismatch: %#v %v", execution, err)
	}

	if _, err := store.db.Exec(`INSERT INTO requests(request_id,request_hash,request_json,status,created_at,expires_at)
VALUES('corrupt','hash','{',?,?,?)`, model.Created, now(), time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("corrupt"); err == nil {
		t.Fatal("corrupt request JSON was accepted")
	}
	if err := store.transaction(func(*sql.Tx) error { return fmt.Errorf("rollback") }); err == nil {
		t.Fatal("transaction callback failure ignored")
	}

	closed, err := Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := closed.Get("x"); err == nil {
		t.Fatal("closed database read succeeded")
	}
	if err := closed.Transition("x", model.Waiting, model.Created); err == nil {
		t.Fatal("closed database transition succeeded")
	}
	if _, err := closed.Pending(); err == nil {
		t.Fatal("closed pending query succeeded")
	}
	if _, err := closed.RecentPending(10, 0, true); err == nil {
		t.Fatal("closed recent-pending query succeeded")
	}
	if _, err := closed.All(); err == nil {
		t.Fatal("closed database query succeeded")
	}
	if _, err := closed.Recent(10, 0, true); err == nil {
		t.Fatal("closed recent query succeeded")
	}
	if _, err := closed.ApprovalFor("x"); err == nil {
		t.Fatal("closed approval query succeeded")
	}
	if err := closed.BeginExecution("x", model.Created); err == nil {
		t.Fatal("closed begin-execution succeeded")
	}
	if err := closed.FinishExecution("x", nil, "TERM"); err == nil {
		t.Fatal("closed finish-execution succeeded")
	}
	if _, err := closed.Execution("x"); err == nil {
		t.Fatal("closed execution query succeeded")
	}
	if _, _, err := closed.AppendOutput("x", 0, "stdout", []byte("x"), 1); err == nil {
		t.Fatal("closed output append succeeded")
	}
	if _, err := closed.Output("x"); err == nil {
		t.Fatal("closed output query succeeded")
	}
	if err := closed.RecordSecurityEvent("x", "", "", "x"); err == nil {
		t.Fatal("closed audit write succeeded")
	}
	if err := closed.ExpireOutstanding(); err == nil {
		t.Fatal("closed expiry succeeded")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing", "state.db")); err == nil {
		t.Fatal("database in missing directory opened")
	}
}

func TestStorageLimitOutputPagingAndRetention(t *testing.T) {
	limited, err := Open(filepath.Join(t.TempDir(), "limited.db"))
	if err != nil {
		t.Fatal(err)
	}
	limited.SetMaxBytes(1)
	if err := limited.Create(testRequest("too-large", 1000, time.Now().Add(time.Minute)), "hash"); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("storage limit did not reject request: %v", err)
	}
	if err := limited.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index := 0; index < 3; index++ {
		request := testRequest(fmt.Sprintf("cancelled-%d", index), 1000, time.Now().Add(time.Hour))
		request.CreatedAt = time.Now().Add(time.Duration(index-3) * time.Hour).UTC().Format(time.RFC3339Nano)
		if err := store.Create(request, "hash"); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(request.RequestID, model.Cancelled, model.Waiting); err != nil {
			t.Fatal(err)
		}
	}
	approved := testRequest("approved-denial", 1000, time.Now().Add(time.Hour))
	if err := store.Create(approved, "approved-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(approved.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	denial := testApproval(approved, "approved-hash", "denial")
	denial.Decision = "deny"
	if err := store.AcceptApproval(denial); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneUnapproved(time.Now().Add(-24*time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	items, err := store.All()
	if err != nil || len(items) != 2 {
		t.Fatalf("retention mismatch: %#v %v", items, err)
	}
	if item, _ := store.Get(approved.RequestID); item == nil {
		t.Fatal("approved audit record was pruned")
	}
	if err := store.PruneUnapproved(time.Now(), -1); err == nil {
		t.Fatal("invalid retention limit accepted")
	}
	if err := store.PruneUnapproved(time.Time{}, 100); err != nil {
		t.Fatalf("empty retention pass failed: %v", err)
	}

	outputRequest := testRequest("paged-output", 1000, time.Now().Add(time.Hour))
	if err := store.Create(outputRequest, "output-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(outputRequest.RequestID, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(outputRequest.RequestID, 0, "stdout", []byte("first"), 100); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(outputRequest.RequestID, 1, "stdout", []byte("second"), 100); err != nil {
		t.Fatal(err)
	}
	page, more, err := store.OutputAfter(outputRequest.RequestID, 0, 5)
	if err != nil || !more || len(page) != 1 || string(page[0].Data) != "first" {
		t.Fatalf("output page mismatch: %#v %v %v", page, more, err)
	}
	page, more, err = store.OutputAfter(outputRequest.RequestID, 1, 5)
	if err != nil || more || len(page) != 1 || string(page[0].Data) != "second" {
		t.Fatalf("output continuation mismatch: %#v %v %v", page, more, err)
	}
	closed, err := Open(filepath.Join(t.TempDir(), "closed-retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closed.PruneUnapproved(time.Now(), 1); err == nil {
		t.Fatal("retention query on closed database succeeded")
	}
}

func TestRetentionFailsClosedOnDeletionErrors(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "retention-errors.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("failed-unapproved", 1000, time.Now().Add(time.Hour))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(request.RequestID, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(request.RequestID, 0, "stdout", []byte("output"), 100); err != nil {
		t.Fatal(err)
	}
	code := int32(1)
	if err := store.FinishExecution(request.RequestID, &code, ""); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"output_chunks", "executions", "requests"} {
		trigger := "fail_delete_" + target
		if _, err := store.db.Exec("CREATE TRIGGER " + trigger + " BEFORE DELETE ON " + target + " BEGIN SELECT RAISE(ABORT,'blocked'); END"); err != nil {
			t.Fatal(err)
		}
		if err := store.PruneUnapproved(time.Now(), 0); err == nil {
			t.Fatalf("%s deletion failure was ignored", target)
		}
		if _, err := store.db.Exec("DROP TRIGGER " + trigger); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PruneUnapproved(time.Now(), 0); err != nil {
		t.Fatal(err)
	}
}

func TestOutputAndExecutionEdgeCases(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("edge-execution", 1000, time.Now().Add(time.Hour))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput("missing", 0, "stdout", []byte("x"), 1); err == nil {
		t.Fatal("output for an unknown request was accepted")
	}
	if err := store.BeginExecution("missing", model.Created); err == nil {
		t.Fatal("unknown request began execution")
	}
	if err := store.FinishExecution("missing", nil, "TERM"); err == nil {
		t.Fatal("unknown request finished execution")
	}
	truncated, stored, err := store.AppendOutput(request.RequestID, 0, "stdout", []byte("abc"), 10)
	if err != nil || truncated || string(stored) != "abc" {
		t.Fatalf("ordinary output append failed: %v %q %v", truncated, stored, err)
	}
	if err := store.BeginExecution(request.RequestID, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishExecution(request.RequestID, nil, "KILL"); err != nil {
		t.Fatal(err)
	}
	execution, err := store.Execution(request.RequestID)
	if err != nil || execution == nil || execution.ExitCode != nil || execution.Signal != "KILL" {
		t.Fatalf("signal-only execution mismatch: %#v %v", execution, err)
	}

	withoutApproval := testRequest("approval-missing", 1000, time.Now().Add(time.Hour))
	if err := store.Create(withoutApproval, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE requests SET status=? WHERE request_id=?", model.Approved, withoutApproval.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(withoutApproval.RequestID, model.Approved); err == nil {
		t.Fatal("execution consumed a nonexistent approval")
	}
	item, err := store.Get(withoutApproval.RequestID)
	if err != nil || item == nil || item.Status != model.Approved {
		t.Fatalf("failed approval consumption did not roll back: %#v %v", item, err)
	}

	duplicate := testRequest("duplicate-execution", 1000, time.Now().Add(time.Hour))
	if err := store.Create(duplicate, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(duplicate.RequestID, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE requests SET status=? WHERE request_id=?", model.Created, duplicate.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(duplicate.RequestID, model.Created); err == nil {
		t.Fatal("duplicate execution record was accepted")
	}
}

func TestLegacyHostColumnIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("legacy-host", 1000, time.Now().Add(time.Hour))
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE requests (
 request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, request_json TEXT NOT NULL,
 status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 output_bytes INTEGER NOT NULL DEFAULT 0, output_truncated INTEGER NOT NULL DEFAULT 0,
 host_id TEXT NOT NULL
) STRICT;
CREATE TABLE outbound_events (event_id TEXT);
CREATE TABLE used_nonces (nonce TEXT);
INSERT INTO requests(request_id,request_hash,request_json,status,created_at,expires_at,host_id)
VALUES(?,?,?,?,?,?,?)`, request.RequestID, "hash", string(raw), model.Waiting, request.CreatedAt, request.ExpiresAt, "old-host")
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var hostColumns int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name='host_id'`).Scan(&hostColumns); err != nil {
		t.Fatal(err)
	}
	if hostColumns != 0 {
		t.Fatal("legacy host binding column was retained")
	}
	item, err := store.Get(request.RequestID)
	if err != nil || item == nil || item.Status != model.PolicyRejected {
		t.Fatalf("legacy request was not rejected: %#v %v", item, err)
	}
}

func TestOpenRejectsIncompatibleExistingSchemas(t *testing.T) {
	for _, test := range []struct {
		name   string
		schema string
	}{
		{
			name: "recovery schema",
			schema: `CREATE TABLE requests (
 request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, request_json TEXT NOT NULL,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL
) STRICT;`,
		},
		{
			name:   "migration schema",
			schema: `CREATE TABLE server_state (unexpected TEXT) STRICT;`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "incompatible.db")
			database, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(test.schema); err != nil {
				database.Close()
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if store, err := Open(path); err == nil {
				store.Close()
				t.Fatal("incompatible schema was accepted")
			}
		})
	}
}

func TestCorruptRowsAndStorageConflictsFailClosed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("corrupt-query", 1000, time.Now().Add(time.Hour))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DROP TRIGGER requests_immutable"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE requests SET request_json='{' WHERE request_id=?", request.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecentPending(10, 0, true); err == nil {
		t.Fatal("recent query returned corrupt request JSON")
	}
	if _, err := store.All(); err == nil {
		t.Fatal("status query returned corrupt request JSON")
	}

	outputRequest := testRequest("output-conflict", 1000, time.Now().Add(time.Hour))
	if err := store.Create(outputRequest, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(outputRequest.RequestID, 0, "stdout", []byte("first"), 100); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendOutput(outputRequest.RequestID, 0, "stdout", []byte("duplicate"), 100); err == nil {
		t.Fatal("duplicate output sequence was accepted")
	}
	if _, err := store.db.Exec("UPDATE requests SET output_bytes=100 WHERE request_id=?", outputRequest.RequestID); err != nil {
		t.Fatal(err)
	}
	truncated, stored, err := store.AppendOutput(outputRequest.RequestID, 1, "stdout", []byte("over-cap"), 10)
	if err != nil || !truncated || len(stored) != 0 {
		t.Fatalf("over-cap output mismatch: %v %q %v", truncated, stored, err)
	}
}

func TestOutputRejectsMalformedStoredRows(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("bad-output", 1000, time.Now().Add(time.Hour))
	if err := store.Create(request, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DROP TABLE output_chunks"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TABLE output_chunks (
 request_id TEXT NOT NULL, sequence TEXT NOT NULL, stream TEXT NOT NULL, data BLOB NOT NULL
) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("INSERT INTO output_chunks VALUES(?,?,?,?)", request.RequestID, "not-a-number", "stdout", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Output(request.RequestID); err == nil {
		t.Fatal("malformed output sequence was accepted")
	}
}

func TestTransitionFailsWhenRequestStorageIsUnavailable(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.Exec("DROP TABLE requests"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition("missing", model.Waiting, model.Created); err == nil {
		t.Fatal("transition succeeded without request storage")
	}
}

func TestDatabaseInterferenceCannotBypassAtomicTransitions(t *testing.T) {
	t.Run("update rejected", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		request := testRequest("blocked-update", 1000, time.Now().Add(time.Minute))
		if err := store.Create(request, "hash"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`CREATE TRIGGER block_status_update BEFORE UPDATE OF status ON requests
BEGIN SELECT RAISE(ABORT,'blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(request.RequestID, model.Waiting, model.Created); err == nil {
			t.Fatal("failed database update was reported as a transition")
		}
	})

	t.Run("zero rows rejected", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		request := testRequest("ignored-update", 1000, time.Now().Add(time.Minute))
		if err := store.Create(request, "hash"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`CREATE TRIGGER ignore_status_update BEFORE UPDATE OF status ON requests
BEGIN SELECT RAISE(IGNORE); END`); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(request.RequestID, model.Waiting, model.Created); err == nil {
			t.Fatal("zero-row update was reported as a transition")
		}
	})

	t.Run("approval consumption rejected", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		request := testRequest("blocked-consumption", 1000, time.Now().Add(time.Minute))
		if err := store.Create(request, "hash"); err != nil {
			t.Fatal(err)
		}
		if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
			t.Fatal(err)
		}
		if err := store.AcceptApproval(testApproval(request, "hash", "blocked-consumption-approval")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`CREATE TRIGGER block_approval_consumption BEFORE UPDATE OF consumed_at ON approvals
BEGIN SELECT RAISE(ABORT,'blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginExecution(request.RequestID, model.Approved); err == nil {
			t.Fatal("execution began without atomically consuming approval")
		}
		item, err := store.Get(request.RequestID)
		if err != nil || item == nil || item.Status != model.Approved {
			t.Fatalf("failed consumption did not roll back transition: %#v %v", item, err)
		}
	})
}
