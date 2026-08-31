package state

import (
	"path/filepath"
	"testing"
	"time"

	"shudo.local/shudo/internal/model"
)

func TestAdversarialMalformedApprovalsNeverEnterState(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("malformed-approval-target", 1000, time.Now().Add(time.Minute))
	if err := store.Create(request, "request-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	valid := testApproval(request, "request-hash", "approval-id")
	tests := []struct {
		name   string
		mutate func(*model.Approval)
	}{
		{"version", func(value *model.Approval) { value.Version = 2 }},
		{"approval ID", func(value *model.Approval) { value.ApprovalID = "" }},
		{"request ID", func(value *model.Approval) { value.RequestID = "" }},
		{"request hash", func(value *model.Approval) { value.RequestHash = "" }},
		{"actor", func(value *model.Approval) { value.ApprovedBy.Subject = "" }},
		{"decision", func(value *model.Approval) { value.Decision = "approve-always" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := store.AcceptApproval(candidate); err == nil {
				t.Fatal("malformed approval was accepted")
			}
		})
	}
	item, err := store.Get(request.RequestID)
	if err != nil || item == nil || item.Status != model.Waiting {
		t.Fatalf("malformed approvals changed request state: %#v %v", item, err)
	}
	if approval, err := store.ApprovalFor(request.RequestID); err != nil || approval != nil {
		t.Fatalf("malformed approval was persisted: %#v %v", approval, err)
	}
}

func TestAdversarialAppendOnlySecurityRecordsRejectTampering(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := testRequest("append-only-target", 1000, time.Now().Add(time.Minute))
	if err := store.Create(request, "request-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(request.RequestID, model.Waiting, model.Created); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptApproval(testApproval(request, "request-hash", "append-only-approval")); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSecurityEvent("attack.detected", request.RequestID, "input-hash", "original"); err != nil {
		t.Fatal(err)
	}
	attacks := []struct {
		name  string
		query string
	}{
		{"rewrite request", "UPDATE requests SET request_json='{}' WHERE request_id='append-only-target'"},
		{"rewrite approval", "UPDATE approvals SET approval_json='{}' WHERE request_id='append-only-target'"},
		{"delete approval", "DELETE FROM approvals WHERE request_id='append-only-target'"},
		{"rewrite audit", "UPDATE security_events SET detail='hidden' WHERE type='attack.detected'"},
		{"delete audit", "DELETE FROM security_events WHERE type='attack.detected'"},
	}
	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			if _, err := store.db.Exec(attack.query); err == nil {
				t.Fatal("append-only record was modified")
			}
		})
	}
}
