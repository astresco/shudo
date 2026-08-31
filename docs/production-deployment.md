# Production deployment

Shudo deliberately reduces credential exposure; it does not make arbitrary root commands safe. Treat the daemon and its review workflow as security-critical.

## Account layout

Create a dedicated Unix account for each agent or agent trust domain. Add it to `shudo`, but not to `sudo`, `wheel`, `docker`, `lxd`, `disk`, `systemd-journal`, or other privilege-bearing groups. Do not share that account with the human reviewer.

Use a separate terminal and preferably a separate human login for review. The reviewer may run `sudo -i` and approve as root, but should first invalidate reusable sudo state with `sudo -k` in agent-accessible accounts. Never type a password into an agent-controlled terminal, shared tmux session, automation log, or command argument.

If the agent runs as your normal desktop account, Shudo can keep the password out of the command request, but it cannot stop the agent from using that account's cached sudo timestamp, SSH agent, desktop session, ptrace rights, or other ambient authority. A dedicated non-sudo agent account is the production boundary.

## Installation

Build on a controlled builder, retain checksums and provenance, and copy only the two static binaries plus reviewed systemd/config/policy files to the host. Root-owned production files must not be writable by the agent:

```text
/usr/local/bin/shudo          root:root 0755
/usr/local/sbin/shudod        root:root 0755
/etc/shudo                    root:root 0700
/etc/shudo/config.yaml        root:root 0644
/etc/shudo/policy.yaml        root:root 0644
/var/lib/shudo                root:root 0700
/run/shudo                    root:shudo 0750
/run/shudo/shudo.sock         root:shudo 0660
```

The included source-tree installer is convenient for development. For production, package the artifacts and verify them before privileged installation; do not run a root installer from an agent-writable checkout.

## Operations

- Policy supports only `require-approval` and `deny`; use `deny` for Shudo's own files and sensitive credential-management tools.
- Review the full command and reason. Approval displays the complete execution docket and exact hash; use a separate `--show ID --verbose` pass whenever quoting, interpreters, scripts, or unusual Unicode are involved.
- Monitor database size and rate-limit rejections. Put `/var/lib/shudo` on a quota-limited filesystem when host layout permits it.
- Keep request timeouts short. Set execution limits and output caps for the workload.
- Back up the root-only SQLite audit state, monitor daemon failures and policy rejections, and rotate logs without exposing command output.
- Upgrade by stopping `shudod`, replacing the binary atomically, and restarting. Old remote-era pending records are rejected during the local-only database migration.
- Incident response is ordinary local-root incident response: stop and mask `shudod`, preserve `/var/lib/shudo/shudo.db`, remove affected accounts from `shudo`, inspect approved commands and persistence, then rebuild the host if root compromise is plausible.
