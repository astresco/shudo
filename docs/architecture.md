# Architecture

Shudo has two statically compiled Go executables:

- `shudo` submits commands, watches its own requests, and provides root-only review commands.
- `shudod` owns the request database, evaluates policy, verifies decisions, and executes approved commands as root.

They use protobuf/gRPC over `/run/shudo/shudo.sock`. This is a local framing choice, not a network API. The daemon opens no TCP socket and contains no remote client. Transport encryption is not useful on this boundary: the kernel provides local isolation and authenticated `SO_PEERCRED` data, while TLS would add a reusable local key without authenticating the Unix process as strongly as the kernel does.

## Authority

On every connection, the daemon obtains PID, UID, and GID from the accepted Unix socket. These values never come from a protobuf body.

| Operation | Non-root peer | UID 0 peer |
| --- | --- | --- |
| Submit | yes | yes |
| Watch/cancel | own requests | all requests |
| List/inspect | no | all requests |
| Approve/deny | no | yes |

The socket is `root:shudo` mode `0660`; its directory is `root:shudo` mode `0750`. Group membership grants request submission and access to the submitter's live request stream, not review visibility or approval.

## Request lifecycle

The daemon resolves the executable with a fixed safe `PATH`, resolves symlinks,
captures executable identity and SHA-256 under a size limit, resolves the working
directory, obtains requester identity, evaluates local deny policy, then
canonicalizes and hashes the immutable request. Every accepted request enters
`WAITING_APPROVAL`; policy has no automatic execution action. State and request
bytes are committed to SQLite before the request becomes visible.

The local states retained in the database are `CREATED`, `WAITING_APPROVAL`, `APPROVED`, `DENIED`, `EXPIRED`, `EXECUTING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, and `POLICY_REJECTED`. Older remote-era state names are understood only so upgrades can reject them safely. Invalid or concurrent transitions fail.

Approval requires the client to echo the hash displayed during inspection and
creates an append-only decision bound to that request ID and hash. The database
transaction both inserts the unique approval and changes `WAITING_APPROVAL` to
`APPROVED` or `DENIED`. Repeating the same decision is idempotent and returns the
original approval ID; a conflicting decision fails. Inspection exposes the
stored decision so a client can resolve a response lost after commit. Before
execution, the daemon repeats policy and hash
checks, opens verified descriptors for the working directory, executable, and
any shebang interpreter, then atomically consumes the approval and moves
`APPROVED` to `EXECUTING` before spawning.

The helper enters the pinned working-directory descriptor with `fchdir` and
executes the verified executable descriptor. Scripts are invoked through a
verified interpreter descriptor with the script descriptor as input, so neither
object is reopened by its submitted pathname. There is no shell interpolation;
a shell runs only if it is the requested executable. The root environment is
fixed to `PATH`, `HOME=/root`, and `LANG=C.UTF-8` with no request overrides.

Output is drained concurrently, stored under per-request and global database
caps, and replayed from the requested sequence in bounded batches. Submission
rate/concurrency and watcher counts are bounded. Unapproved terminal history is
pruned by age and count; approved audit records are retained. The original
request timeout bounds both approval waiting and execution, with the daemon
execution limit as an additional ceiling. A daemon restart marks interrupted
executions failed and resumes approved-but-not-started work only after all
checks are repeated.
