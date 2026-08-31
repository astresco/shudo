# CLI reference

`shudo` has two modes. Command mode submits a privileged operation from any member of the `shudo` Unix group. Every review command requires the CLI process to already be UID 0.

The CLI connects only to `/run/shudo/shudo.sock`. `SHUDO_SOCKET_PATH` exists for the isolated development daemon and should not be set in normal installations.

## Submit a command

The direct and explicit forms are equivalent:

```console
shudo --reason "Install jq for the build" apt-get install -y jq
shudo exec --reason "Install jq for the build" -- apt-get install -y jq
```

Use `--` before a command whose arguments might otherwise look like Shudo options:

```console
shudo --reason "Inspect service logs" -- journalctl -u nginx --since -1h
```

Submission options:

| Option | Meaning |
| --- | --- |
| `--reason TEXT` | Required justification. An interactive terminal prompts when omitted. |
| `--timeout DURATION` | Total approval-and-execution deadline; defaults to `5m`. Range: `1s` to `24h`. |
| `--detach` | Submit, print the full request ID, and return without watching. |
| `--json` | Emit newline-delimited machine-readable lifecycle records. |
| `--verbose` | Print request and approval lifecycle details to stderr. |

Environment overrides are not supported. Arguments, reasons, and command output
are retained in the audit database; do not place secrets in them.

Without `--detach`, Shudo waits, streams stdout and stderr, and returns the executed command's exit code. It is otherwise quiet. A denial, policy rejection, expiry, or transport failure returns nonzero.

Interrupting the waiting CLI asks the daemon to cancel a request that has not started. Once an approved command is executing, closing the CLI does not imply that the root process was killed; inspect the request history before retrying a non-idempotent operation.

Shudo never interprets shell syntax. This executes `printf` with literal arguments:

```console
shudo --reason "Demonstrate argv handling" printf '%s\n' 'a | b'
```

To request a shell, make the shell explicit; the docket marks it as risky:

```console
shudo --reason "Run an explicit pipeline" /bin/bash -lc 'printf x | wc -c'
```

## List and inspect

```console
shudo --pending
shudo --requests
shudo --show [ID-PREFIX]
shudo --show [ID-PREFIX] --verbose
```

`--pending` shows requests awaiting a decision. `--requests` shows the 50 newest records. Both commands, along with `--show`, `--approve`, and `--deny`, are root-only. The CLI rejects non-root review before connecting, and the daemon independently verifies UID 0 using Linux `SO_PEERCRED`.

Human selection and confirmation do not consume RPC deadline time; every
network operation receives a fresh bounded context. If a decision response is
lost, the CLI performs a read-only inspection and reports the authoritative
stored decision. A request still shown as pending was not committed and may be
retried. Repeating the same decision returns the original approval ID and never
executes the request twice; attempting the opposite decision fails.

Listings show the first eight characters of each request ID. `--show`, `--approve`, and `--deny` accept any unique prefix of at least four characters. An ambiguous, expired, non-pending, or unknown selector fails closed. A full UUID remains valid even when an older record no longer appears in the 50-item recent list.

Omitting the selector from `--show` opens a numbered picker over recent requests. Technical fields are hidden by default; `--verbose` adds exact indexed arguments, UID/GID, policy result, and request hash.

## Decide as root

```console
shudo --approve
shudo --deny
```

With no selector, both commands display a current numbered docket on `/dev/tty`
and ask for one number. Approval then displays the resolved executable, exact
indexed argv, cwd, environment, risk warnings, requester, expiry, and request
hash and requires a second confirmation. The server rejects approval unless the
client echoes that exact hash.

For noninteractive approval, first inspect the request and then supply its full
hash explicitly:

```console
shudo --show 26fda105 --json
shudo --approve 26fda105 --confirm-hash FULL_64_CHARACTER_HASH --json
shudo --deny 9de567e2
```

Decision commands do not ask for a reason. Membership in `shudo`, possession of a request ID, and access to another user's terminal grant neither review visibility nor decision authority.

## JSON mode

Submission JSON is newline-delimited because output and state arrive over time. Binary output is carried as unpadded URL-safe Base64 in `dataBase64` with its stream in `stream`.

Review commands return ordinary JSON values:

```console
shudo --requests --json
shudo --show 26fda105 --json
shudo --approve 26fda105 --confirm-hash FULL_64_CHARACTER_HASH --json
```

Do not treat a request ID as a secret or approval token. It identifies immutable local state; authority always comes from the Unix peer credentials independently.
