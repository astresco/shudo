---
name: use-shudo
description: Submit a specific local command to Shudo for human-approved root execution and handle its result safely. Use when an unprivileged agent needs one privileged operation on a Linux host running shudod; do not use for ordinary unprivileged work, remote execution, or approval decisions.
---

# Use Shudo

Shudo lets an agent request an exact root command without receiving a password or reusable privilege. A human reviews the request from a separate root session. Submission does not imply approval.

## Submit the request

Run the smallest command that completes the authorized task:

```sh
shudo --reason "Install jq required by the project build" -- apt-get install -y jq
```

- Always supply a concrete `--reason`; agents cannot rely on an interactive prompt.
- Keep executable and arguments separate. Use `--` so command flags cannot be parsed as Shudo flags.
- Do not bundle unrelated work, request an interactive root shell, or seek reusable credentials.
- Do not use shell operators directly. If shell grammar is necessary, request an explicit shell and make the whole program reviewable, for example `shudo --reason "Count matching service log lines" -- /bin/bash -lc 'journalctl -u nginx | grep -c error'`.
- Use `--timeout` when five minutes is unsuitable. The timeout covers both approval wait and execution.
- Avoid `--detach` when later work depends on success. A detached request is not a completed operation.
- Do not place secrets in the reason or arguments; request details and output are retained locally for review and audit. Shudo rejects request environment overrides.

Shudo normally stays quiet while waiting, streams the command's stdout and stderr after approval, and exits with the command's exit code.

## Handle the result

Treat exit code zero as success only if the output and resulting state also match the task. On denial, expiry, policy rejection, socket failure, or nonzero command exit, report the failure and relevant output.

Do not automatically retry a command whose execution status is uncertain, especially if it is not idempotent. Report the request ID when available and ask the root reviewer to inspect it. Review commands are unavailable to non-root agents.

If `shudo` is missing, the socket is inaccessible, or `shudod` is unavailable, report the exact error. Do not install, reconfigure, restart, approve, or weaken Shudo unless the user separately authorizes that work.

Approval and denial belong to the human's root session. Never invoke `shudo --approve` or `shudo --deny` as part of the requesting-agent workflow.
