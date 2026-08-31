package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"shudo.local/shudo/internal/model"
)

var transitions = map[string]map[string]bool{
	model.Created:        {model.PolicyRejected: true, model.Queued: true, model.Waiting: true, model.Executing: true, model.Cancelled: true, model.Expired: true},
	model.Queued:         {model.Synced: true, model.Waiting: true, model.PolicyRejected: true, model.Cancelled: true, model.Expired: true},
	model.Synced:         {model.Waiting: true, model.PolicyRejected: true, model.Cancelled: true, model.Expired: true},
	model.Waiting:        {model.Approved: true, model.Denied: true, model.PolicyRejected: true, model.Cancelled: true, model.Expired: true},
	model.Approved:       {model.Executing: true, model.PolicyRejected: true, model.Expired: true},
	model.Executing:      {model.Succeeded: true, model.Failed: true},
	model.PolicyRejected: {}, model.Denied: {}, model.Expired: {}, model.Succeeded: {},
	model.Failed: {}, model.Cancelled: {},
}

type StoredRequest struct {
	Request         model.ExecutionRequest
	RequestHash     string
	Status          string
	OutputBytes     int64
	OutputTruncated bool
}

type OutputChunk struct {
	Sequence uint64
	Stream   string
	Data     []byte
}

type ExecutionResult struct {
	ExitCode   *int32
	Signal     string
	StartedAt  string
	FinishedAt string
}

type Store struct {
	db       *sql.DB
	path     string
	maxBytes int64
	mu       sync.Mutex
}

var ErrStorageLimit = errors.New("state storage limit reached")

func Open(path string) (*Store, error) {
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	store := &Store{db: database, path: path}
	if _, err := database.Exec(`
PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS requests (
 request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
 request_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 output_bytes INTEGER NOT NULL DEFAULT 0, output_truncated INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE IF NOT EXISTS approvals (
 approval_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, approval_json TEXT NOT NULL,
 received_at TEXT NOT NULL, consumed_at TEXT, FOREIGN KEY(request_id) REFERENCES requests(request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS executions (
 request_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
 exit_code INTEGER, signal TEXT, FOREIGN KEY(request_id) REFERENCES requests(request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS output_chunks (
 request_id TEXT NOT NULL, sequence INTEGER NOT NULL, stream TEXT NOT NULL, data BLOB NOT NULL,
 PRIMARY KEY(request_id,sequence), FOREIGN KEY(request_id) REFERENCES requests(request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS server_state (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS security_events (
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, request_id TEXT,
 input_hash TEXT, detail TEXT NOT NULL, occurred_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS requests_immutable
BEFORE UPDATE OF request_hash,request_json,created_at,expires_at ON requests
BEGIN SELECT RAISE(ABORT,'immutable request fields cannot change'); END;
CREATE TRIGGER IF NOT EXISTS approvals_immutable
BEFORE UPDATE OF approval_id,request_id,approval_json,received_at ON approvals
BEGIN SELECT RAISE(ABORT,'immutable approval fields cannot change'); END;
CREATE TRIGGER IF NOT EXISTS approvals_append_only
BEFORE DELETE ON approvals BEGIN SELECT RAISE(ABORT,'approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS security_events_append_only_update
BEFORE UPDATE ON security_events BEGIN SELECT RAISE(ABORT,'security events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS security_events_append_only_delete
BEFORE DELETE ON security_events BEGIN SELECT RAISE(ABORT,'security events are append-only'); END;
`); err != nil {
		database.Close()
		return nil, err
	}
	if err := store.recoverInterrupted(); err != nil {
		database.Close()
		return nil, err
	}
	if err := store.migrateLocalOnly(); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SetMaxBytes(maxBytes int64) { s.maxBytes = maxBytes }

func (s *Store) Create(request model.ExecutionRequest, hash string) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if !s.hasCapacity(int64(len(raw)) + 4096) {
		return ErrStorageLimit
	}
	_, err = s.db.Exec(`INSERT INTO requests
(request_id,request_hash,request_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?)`,
		request.RequestID, hash, string(raw), model.Created, request.CreatedAt, request.ExpiresAt)
	return err
}

func (s *Store) Get(requestID string) (*StoredRequest, error) {
	return getFrom(s.db, requestID)
}

func getFrom(query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, requestID string) (*StoredRequest, error) {
	var raw string
	var stored StoredRequest
	var truncated int
	err := query.QueryRowContext(context.Background(), `SELECT request_json,request_hash,status,output_bytes,output_truncated
FROM requests WHERE request_id=?`, requestID).Scan(&raw, &stored.RequestHash, &stored.Status, &stored.OutputBytes, &truncated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), &stored.Request); err != nil {
		return nil, err
	}
	stored.OutputTruncated = truncated != 0
	return &stored, nil
}

func (s *Store) Transition(requestID, next, expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transaction(func(tx *sql.Tx) error { return transition(tx, requestID, next, expected) })
}

func transition(tx *sql.Tx, requestID, next, expected string) error {
	current, err := getFrom(tx, requestID)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("unknown request")
	}
	if expected != "" && current.Status != expected {
		return fmt.Errorf("expected %s, found %s", expected, current.Status)
	}
	if !transitions[current.Status][next] {
		return fmt.Errorf("invalid transition %s -> %s", current.Status, next)
	}
	result, err := tx.Exec("UPDATE requests SET status=? WHERE request_id=? AND status=?", next, requestID, current.Status)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("concurrent state transition")
	}
	return nil
}

func (s *Store) Pending() ([]StoredRequest, error) {
	if err := s.ExpireOutstanding(); err != nil {
		return nil, err
	}
	return s.byStatuses(model.Waiting)
}

func (s *Store) RecentPending(limit int, uid uint32, allUsers bool) ([]StoredRequest, error) {
	if err := s.ExpireOutstanding(); err != nil {
		return nil, err
	}
	return s.recent(limit, uid, allUsers, model.Waiting)
}

func (s *Store) Recent(limit int, uid uint32, allUsers bool) ([]StoredRequest, error) {
	return s.recent(limit, uid, allUsers, model.Created, model.Queued, model.Synced, model.Waiting,
		model.Approved, model.Executing, model.PolicyRejected, model.Denied, model.Expired,
		model.Succeeded, model.Failed, model.Cancelled)
}

func (s *Store) recent(limit int, uid uint32, allUsers bool, statuses ...string) ([]StoredRequest, error) {
	if limit < 1 || limit > 1_000 || len(statuses) == 0 {
		return nil, errors.New("invalid recent request query")
	}
	placeholders := "?"
	arguments := []any{statuses[0]}
	for _, status := range statuses[1:] {
		placeholders += ",?"
		arguments = append(arguments, status)
	}
	query := "SELECT request_id FROM requests WHERE status IN (" + placeholders + ")"
	if !allUsers {
		query += " AND CAST(json_extract(request_json,'$.requester.uid') AS INTEGER)=?"
		arguments = append(arguments, uid)
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	arguments = append(arguments, limit)
	rows, err := s.db.Query(query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]StoredRequest, 0, len(ids))
	for _, id := range ids {
		item, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		if item != nil {
			result = append(result, *item)
		}
	}
	return result, nil
}

func (s *Store) All() ([]StoredRequest, error) {
	return s.byStatuses(model.Created, model.Queued, model.Synced, model.Waiting, model.Approved,
		model.Executing, model.PolicyRejected, model.Denied, model.Expired, model.Succeeded,
		model.Failed, model.Cancelled)
}

func (s *Store) Approved() ([]StoredRequest, error) { return s.byStatuses(model.Approved) }

func (s *Store) OutstandingCounts(uid uint32) (perUID, total int, err error) {
	statuses := []string{model.Created, model.Queued, model.Synced, model.Waiting, model.Approved, model.Executing}
	query := `SELECT
COUNT(*) FILTER (WHERE CAST(json_extract(request_json,'$.requester.uid') AS INTEGER)=?),
COUNT(*) FROM requests WHERE status IN (?,?,?,?,?,?)`
	err = s.db.QueryRow(query, uid, statuses[0], statuses[1], statuses[2], statuses[3], statuses[4], statuses[5]).Scan(&perUID, &total)
	return perUID, total, err
}
func (s *Store) Executed() ([]StoredRequest, error) {
	return s.byStatuses(model.Executing, model.Succeeded, model.Failed)
}
func (s *Store) Cancelled() ([]StoredRequest, error) { return s.byStatuses(model.Cancelled) }

func (s *Store) byStatuses(statuses ...string) ([]StoredRequest, error) {
	placeholders := "?"
	arguments := []any{statuses[0]}
	for _, status := range statuses[1:] {
		placeholders += ",?"
		arguments = append(arguments, status)
	}
	rows, err := s.db.Query("SELECT request_id FROM requests WHERE status IN ("+placeholders+")", arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []StoredRequest
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		item, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		if item != nil {
			result = append(result, *item)
		}
	}
	return result, nil
}

func (s *Store) ExpireOutstanding() error {
	_, err := s.db.Exec(`UPDATE requests SET status=? WHERE status IN (?,?,?,?) AND julianday(expires_at)<=julianday(?)`,
		model.Expired, model.Queued, model.Synced, model.Waiting, model.Approved, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ApprovalFor(requestID string) (*model.Approval, error) {
	var raw string
	err := s.db.QueryRow("SELECT approval_json FROM approvals WHERE request_id=?", requestID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var approval model.Approval
	return &approval, json.Unmarshal([]byte(raw), &approval)
}

func (s *Store) AcceptApproval(approval model.Approval) error {
	return s.AcceptApprovalContext(context.Background(), approval)
}

func (s *Store) AcceptApprovalContext(ctx context.Context, approval model.Approval) error {
	if approval.Version != 1 || approval.ApprovalID == "" || approval.RequestID == "" ||
		approval.RequestHash == "" || approval.ApprovedBy.Subject == "" ||
		(approval.Decision != "approve" && approval.Decision != "deny") {
		return errors.New("invalid approval")
	}
	raw, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transactionContext(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO approvals(approval_id,request_id,approval_json,received_at)
VALUES(?,?,?,?)`, approval.ApprovalID, approval.RequestID, string(raw), now()); err != nil {
			return err
		}
		next := model.Denied
		if approval.Decision == "approve" {
			next = model.Approved
		}
		return transition(tx, approval.RequestID, next, model.Waiting)
	})
}

func (s *Store) BeginExecution(requestID, expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transaction(func(tx *sql.Tx) error {
		if err := transition(tx, requestID, model.Executing, expected); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO executions(request_id,started_at) VALUES(?,?)", requestID, now()); err != nil {
			return err
		}
		if expected == model.Approved {
			result, err := tx.Exec("UPDATE approvals SET consumed_at=? WHERE request_id=? AND consumed_at IS NULL", now(), requestID)
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				return errors.New("approval was not consumed exactly once")
			}
		}
		return nil
	})
}

func (s *Store) FinishExecution(requestID string, exitCode *int32, signal string) error {
	next := model.Failed
	if exitCode != nil && *exitCode == 0 {
		next = model.Succeeded
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transaction(func(tx *sql.Tx) error {
		if err := transition(tx, requestID, next, model.Executing); err != nil {
			return err
		}
		var code any
		if exitCode != nil {
			code = *exitCode
		}
		_, err := tx.Exec("UPDATE executions SET finished_at=?,exit_code=?,signal=? WHERE request_id=?",
			now(), code, nullable(signal), requestID)
		return err
	})
}

func (s *Store) Execution(requestID string) (*ExecutionResult, error) {
	var result ExecutionResult
	var exitCode sql.NullInt32
	var signal, finished sql.NullString
	err := s.db.QueryRow(`SELECT started_at,finished_at,exit_code,signal FROM executions WHERE request_id=?`, requestID).
		Scan(&result.StartedAt, &finished, &exitCode, &signal)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if exitCode.Valid {
		value := exitCode.Int32
		result.ExitCode = &value
	}
	if signal.Valid {
		result.Signal = signal.String
	}
	if finished.Valid {
		result.FinishedAt = finished.String
	}
	return &result, nil
}

func (s *Store) AppendOutput(requestID string, sequence uint64, stream string, data []byte, cap int64) (bool, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.Get(requestID)
	if err != nil {
		return false, nil, err
	}
	if current == nil {
		return false, nil, errors.New("unknown request")
	}
	if current.OutputTruncated {
		return true, nil, nil
	}
	remaining := cap - current.OutputBytes
	if remaining < 0 {
		remaining = 0
	}
	stored := data
	if int64(len(stored)) > remaining {
		stored = stored[:remaining]
	}
	if !s.hasCapacity(int64(len(stored)) + 4096) {
		stored = nil
	}
	truncated := len(stored) < len(data)
	if len(stored) > 0 {
		if _, err := s.db.Exec("INSERT INTO output_chunks(request_id,sequence,stream,data) VALUES(?,?,?,?)",
			requestID, sequence, stream, stored); err != nil {
			return false, nil, err
		}
	}
	_, err = s.db.Exec(`UPDATE requests SET output_bytes=output_bytes+?,output_truncated=? WHERE request_id=?`,
		len(stored), boolInt(truncated), requestID)
	return truncated, stored, err
}

func (s *Store) Output(requestID string) ([]OutputChunk, error) {
	chunks, _, err := s.OutputAfter(requestID, 0, 0)
	return chunks, err
}

func (s *Store) OutputAfter(requestID string, after uint64, maxBytes int64) ([]OutputChunk, bool, error) {
	rows, err := s.db.Query("SELECT sequence,stream,data FROM output_chunks WHERE request_id=? AND sequence>=? ORDER BY sequence", requestID, after)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var result []OutputChunk
	var total int64
	for rows.Next() {
		var chunk OutputChunk
		if err := rows.Scan(&chunk.Sequence, &chunk.Stream, &chunk.Data); err != nil {
			return nil, false, err
		}
		if maxBytes > 0 && len(result) > 0 && total+int64(len(chunk.Data)) > maxBytes {
			return result, true, nil
		}
		result = append(result, chunk)
		total += int64(len(chunk.Data))
	}
	return result, false, rows.Err()
}

func (s *Store) PruneUnapproved(olderThan time.Time, retain int) error {
	if retain < 0 {
		return errors.New("invalid retention limit")
	}
	terminal := []string{model.PolicyRejected, model.Denied, model.Expired, model.Cancelled, model.Failed, model.Succeeded}
	rows, err := s.db.Query(`SELECT r.request_id,r.created_at FROM requests r
WHERE r.status IN (?,?,?,?,?,?)
AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.request_id=r.request_id)
ORDER BY r.created_at DESC`, terminal[0], terminal[1], terminal[2], terminal[3], terminal[4], terminal[5])
	if err != nil {
		return err
	}
	var ids []string
	index := 0
	for rows.Next() {
		var id, createdAt string
		if err := rows.Scan(&id, &createdAt); err != nil {
			rows.Close()
			return err
		}
		created, parseErr := time.Parse(time.RFC3339Nano, createdAt)
		if index >= retain || parseErr != nil || created.Before(olderThan) {
			ids = append(ids, id)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transaction(func(tx *sql.Tx) error {
		for _, id := range ids {
			if _, err := tx.Exec("DELETE FROM output_chunks WHERE request_id=?", id); err != nil {
				return err
			}
			if _, err := tx.Exec("DELETE FROM executions WHERE request_id=?", id); err != nil {
				return err
			}
			if _, err := tx.Exec("DELETE FROM requests WHERE request_id=?", id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) hasCapacity(additional int64) bool {
	if s.maxBytes <= 0 {
		return true
	}
	var current int64
	for _, path := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		if info, err := os.Stat(path); err == nil {
			current += info.Size()
		}
	}
	// Reserve ten percent for decisions, state transitions, and SQLite
	// bookkeeping so an attacker cannot consume the bytes needed to deny work.
	return current+additional <= s.maxBytes-s.maxBytes/10
}

func (s *Store) RecordSecurityEvent(eventType, requestID, inputHash, detail string) error {
	if len(detail) > 512 {
		detail = detail[:512]
	}
	_, err := s.db.Exec(`INSERT INTO security_events(type,request_id,input_hash,detail,occurred_at) VALUES(?,?,?,?,?)`,
		eventType, nullable(requestID), nullable(inputHash), detail, now())
	return err
}

func (s *Store) recoverInterrupted() error {
	nowValue := now()
	_, err := s.db.Exec("UPDATE requests SET status=? WHERE status=?", model.Failed, model.Executing)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("UPDATE executions SET finished_at=?,signal='DAEMON_RESTART' WHERE finished_at IS NULL", nowValue)
	return err
}

func (s *Store) migrateLocalOnly() error {
	var marker string
	err := s.db.QueryRow("SELECT value FROM server_state WHERE key='local_only_v2'").Scan(&marker)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return s.transaction(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE requests SET status=? WHERE status IN (?,?,?,?)`, model.PolicyRejected,
			model.Queued, model.Synced, model.Waiting, model.Approved); err != nil {
			return err
		}
		if _, err := tx.Exec("DROP TABLE IF EXISTS outbound_events"); err != nil {
			return err
		}
		if _, err := tx.Exec("DROP TABLE IF EXISTS used_nonces"); err != nil {
			return err
		}
		var legacyHostColumn int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name='host_id'`).Scan(&legacyHostColumn); err != nil {
			return err
		}
		if legacyHostColumn != 0 {
			if _, err := tx.Exec("ALTER TABLE requests DROP COLUMN host_id"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("DELETE FROM server_state WHERE key='approval_channel_quarantine'"); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO server_state(key,value) VALUES('local_only_v2','enabled')`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO security_events(type,request_id,input_hash,detail,occurred_at)
VALUES('migration.local-only',NULL,NULL,'Remote approval state disabled; old pending requests rejected',?)`, now())
		return err
	})
}

func (s *Store) transaction(operation func(*sql.Tx) error) error {
	return s.transactionContext(context.Background(), operation)
}

func (s *Store) transactionContext(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
