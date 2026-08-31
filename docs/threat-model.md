# Threat model

## Assets and principals

Assets are host root authority, reusable human credentials, request integrity, policy/configuration, command output, and audit state. Principals are an untrusted local agent process, a trusted root reviewer process, the root daemon, and the Linux kernel.

The agent may control all data submitted in its request, issue concurrent or malformed gRPC calls, disconnect, exhaust quotas, replace files it owns, alter mutable command dependencies, and attempt terminal deception. It may be fully malicious. The agent is assumed not already to possess UID 0, a kernel exploit, write access to root-owned Shudo files, or an independent privilege path.

## Security properties

1. Only locally authenticated processes can submit.
2. A non-root process cannot list, inspect, approve, or deny any request. It can only submit, watch, and cancel its own request.
3. A root decision can change only an existing `WAITING_APPROVAL` record.
4. Approval requires confirmation of the inspected canonical request hash; the decision is bound to that ID and hash, is idempotent under retry, and is consumed once.
5. No command is accepted from a decision message; execution data always comes from the immutable local request.
6. Local deny policy cannot be overridden and is evaluated twice.
7. The exact executable is content-checked and executed by verified descriptor without shell interpolation.
8. Expiry, cancellation, replay, concurrent decision, restart, and integrity failures fail closed.
9. The daemon has no network protocol or outbound approval dependency.
10. No policy or request field can execute without a fresh UID 0 approval.

## Attack analysis

| Attack | Defense | Residual risk |
| --- | --- | --- |
| Forge UID/GID in protobuf | No identity fields are accepted; use `SO_PEERCRED` | Kernel/root compromise |
| Call approve as a `shudo` member | RPC checks peer UID equals 0 | Independent local privilege escalation |
| Swap executable, cwd, or shebang interpreter after review | Metadata + SHA-256 checks and descriptor-pinned execution | Kernel/filesystem attacks; other dynamic dependencies |
| Modify persisted request | Canonical hash recomputed at decision and execution | Root can modify both code and DB |
| Lost response, replay, or double approve | Context-bound commit, authoritative reconciliation, idempotent response, unique approval, and atomic consumed timestamp | SQLite/daemon implementation flaw |
| Override deny with approval | Deny precedence and second evaluation | Unsafe policy semantics or writable policy |
| Shell metacharacters in argv | `execve`/spawn semantics; shell is never implicit | Explicit shell/interpreter is inherently dynamic |
| Loader/environment injection | Fixed minimal environment; request overrides rejected | Approved program reads other configuration |
| Terminal escape/deceptive docket | Control characters escaped; verbose exact indexed argv | Human review error, Unicode confusables |
| Resource exhaustion | message, field, pending, rate, concurrency, executable, watcher, output, retention, and database limits | CPU/disk pressure within configured caps; approved commands can consume host resources |
| Steal human sudo password | Shudo never handles it | Agent-controlled terminal/keylogger or shared UID |
| Abuse cached sudo | Outside Shudo | Prevent with dedicated non-sudo agent accounts |
| Network/server compromise | No network/server component exists | Approved command itself may use the network |

## Non-goals

Shudo is not a sandbox, malware detector, command semantic analyzer, mandatory four-eyes system, remote fleet manager, secret manager, or replacement for account isolation. It does not prove that a command is wise; it ensures the root daemon runs only the exact local request that root chose to approve, subject to local policy and integrity checks.
