package model

type Requester struct {
	UID       uint32  `json:"uid"`
	GID       uint32  `json:"gid"`
	PID       *int32  `json:"pid,omitempty"`
	Username  *string `json:"username,omitempty"`
	GroupName *string `json:"groupName,omitempty"`
}

type Execution struct {
	Executable string            `json:"executable"`
	Argv       []string          `json:"argv"`
	Cwd        string            `json:"cwd"`
	Env        map[string]string `json:"env,omitempty"`
}

type FileMetadata struct {
	Path     string  `json:"path"`
	Device   *uint64 `json:"device,omitempty"`
	Inode    *uint64 `json:"inode,omitempty"`
	Size     *uint64 `json:"size,omitempty"`
	OwnerUID *uint32 `json:"ownerUid,omitempty"`
	Mode     *uint32 `json:"mode,omitempty"`
	MtimeNS  *string `json:"mtimeNs,omitempty"`
	CtimeNS  *string `json:"ctimeNs,omitempty"`
	SHA256   string  `json:"sha256"`
}

type WorkingDirectoryMetadata struct {
	Path     string `json:"path"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	OwnerUID uint32 `json:"ownerUid"`
	Mode     uint32 `json:"mode"`
	MtimeNS  string `json:"mtimeNs"`
	CtimeNS  string `json:"ctimeNs"`
}

type RiskMetadata struct {
	Shell                bool     `json:"shell"`
	Interpreter          bool     `json:"interpreter"`
	Script               bool     `json:"script"`
	EnvironmentOverrides bool     `json:"environmentOverrides"`
	Warnings             []string `json:"warnings"`
}

type ExecutionRequest struct {
	Version                  int                      `json:"version"`
	RequestID                string                   `json:"requestId"`
	Requester                Requester                `json:"requester"`
	Execution                Execution                `json:"execution"`
	ExecutableMetadata       FileMetadata             `json:"executableMetadata"`
	InterpreterMetadata      *FileMetadata            `json:"interpreterMetadata,omitempty"`
	InterpreterArgument      *string                  `json:"interpreterArgument,omitempty"`
	WorkingDirectoryMetadata WorkingDirectoryMetadata `json:"workingDirectoryMetadata"`
	Risk                     RiskMetadata             `json:"risk"`
	PolicyResult             string                   `json:"policyResult"`
	Reason                   string                   `json:"reason"`
	CreatedAt                string                   `json:"createdAt"`
	ExpiresAt                string                   `json:"expiresAt"`
	Nonce                    string                   `json:"nonce"`
}

type ApprovedBy struct {
	Subject     string  `json:"subject"`
	DisplayName *string `json:"displayName,omitempty"`
}

type Approval struct {
	Version     int        `json:"version"`
	ApprovalID  string     `json:"approvalId"`
	RequestID   string     `json:"requestId"`
	RequestHash string     `json:"requestHash"`
	Decision    string     `json:"decision"`
	ApprovedBy  ApprovedBy `json:"approvedBy"`
	ApprovedAt  string     `json:"approvedAt"`
	Reason      string     `json:"reason"`
}

const (
	Created        = "CREATED"
	PolicyRejected = "POLICY_REJECTED"
	Queued         = "QUEUED"
	Synced         = "SYNCED"
	Waiting        = "WAITING_APPROVAL"
	Approved       = "APPROVED"
	Denied         = "DENIED"
	Expired        = "EXPIRED"
	Executing      = "EXECUTING"
	Succeeded      = "SUCCEEDED"
	Failed         = "FAILED"
	Cancelled      = "CANCELLED"
)

func Terminal(status string) bool {
	switch status {
	case PolicyRejected, Denied, Expired, Succeeded, Failed, Cancelled:
		return true
	default:
		return false
	}
}
