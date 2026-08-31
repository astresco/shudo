# Security

## What Shudo protects

An unprivileged process receives only the ability to submit an immutable request over a local group-owned socket. It does not receive a password, sudo timestamp, secret key, approval token, setuid binary, generic root RPC, or reusable authorization. A successful approval is consumed once and can execute only the locally stored request to which it is bound.

Approval authority is the kernel credential of the deciding connection: UID 0. There is no role header, user-provided UID, remote signature, web cookie, or config flag that can substitute for it. How the human becomes root is intentionally outside Shudo.

## Mandatory checks

The daemon:

- authenticates all callers with Linux `SO_PEERCRED`;
- denies list and inspect operations to every non-root peer while restricting watch and cancel to the originating UID;
- requires a non-empty submission reason and bounded request fields;
- resolves executables through a fixed safe path and never invokes a shell implicitly;
- hashes RFC 8785-canonical request data, stores requests immutably, and recomputes the hash at decision and execution;
- stores decisions append-only and atomically consumes approvals before spawn;
- requires approval clients to confirm the exact inspected request hash;
- makes identical decision retries idempotent and reconciles ambiguous RPC responses from append-only server state;
- has no automatic allow or environment-override mechanism;
- validates that configuration, policy, database, and socket paths are rooted in trusted directories before startup;
- evaluates local deny policy both before review and before execution;
- hashes and records executable device, inode, ownership, mode, timestamps, and content under a size limit, then executes the verified file descriptor;
- pins the resolved working directory and shebang interpreter as file descriptors through execution;
- starts from `PATH`, `HOME=/root`, and `LANG=C.UTF-8`, rejecting all request environment overrides;
- drains stdout and stderr concurrently under a persisted cap;
- bounds submissions, watchers, database growth, and retained unapproved history; and
- renders agent-controlled terminal text with control characters escaped.

## Important limits

Approval of a root command is approval of everything that command can do. Package managers run maintainer scripts; service managers start mutable units; shells and interpreters execute dynamic code; a command may modify Shudo, policy, sudoers, SSH keys, cron, kernels, or persistent services.

Executable, cwd, and shebang-interpreter descriptors are pinned, but arguments
may still name mutable configs, other directories, device files, network
resources, plugins, response files, or services. The working directory's full
tree is not snapshotted. Review every indirect input.

Command output can contain secrets and is retained in the root-owned database. Do not approve commands that print credentials, and set conservative output limits.

Root can tamper with Shudo or its database; root is the trusted approver and outside the attacker model. A kernel compromise, malicious daemon binary, unsafe policy/config ownership, or privileged group such as Docker also defeats the boundary.

## Cached sudo warning

When an agent shares the human's Unix UID, it may be able to run `sudo -n` while that UID has a valid timestamp. Shudo cannot mediate or revoke that independent sudo authority. For production, run agents as dedicated non-sudo users and conduct review from a different account or console. This is more important than adding encryption to the local socket.
