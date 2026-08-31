# Operator runbook

Shudo is a local systemd service. It has no network deployment, listener, enrollment, remote key, or web component.

## Health checks

```console
systemctl is-active shudod
systemctl status shudod --no-pager
journalctl -u shudod --since today
namei -l /run/shudo/shudo.sock
ss -lxnp | grep /run/shudo/shudo.sock
```

Expected ownership is:

```text
/run/shudo                  root:shudo 0750
/run/shudo/shudo.sock       root:shudo 0660
/var/lib/shudo              root:root  0700
/etc/shudo                  root:root  0700
```

`ss -ltnp` must not show `shudod`. Approved child commands may use the network when their requested operation requires it, but the Shudo control plane is Unix-socket-only.

## Review workflow

From a separate root session:

```console
shudo --pending
shudo --approve
```

After selection, approval always renders the resolved executable, indexed argv,
cwd, warnings, requester, expiry, and request hash, then asks for confirmation.
Use `shudo --show PREFIX --verbose` for a separate inspection pass before
approving interpreters, shells, package managers, service managers, or commands
whose arguments reference mutable files.

Do not enter a sudo password in an agent-controlled terminal. Prefer a dedicated non-sudo agent account and a separate reviewer login or console. If the agent shares the reviewer's Unix UID, invalidate that account's cached sudo authorization and understand the limitations documented in [Security](security.md).

## Logs and state

Systemd logs contain daemon lifecycle and internal failures. Request bodies, decisions, execution results, and capped output are stored in `/var/lib/shudo/shudo.db`, which is root-only SQLite state.

For a consistent backup, either use SQLite's online backup command or stop the daemon before copying all database files:

```console
sqlite3 /var/lib/shudo/shudo.db ".backup '/root/shudo-backup.db'"
```

or:

```console
systemctl stop shudod
cp -a /var/lib/shudo /root/shudo-state-backup
systemctl start shudod
```

Treat backups as sensitive because captured command output may contain confidential data. Do not edit request or approval rows. Database triggers reject mutation of immutable request fields and deletion of approvals/security events, but root remains capable of replacing the database or daemon and is therefore trusted.

## Update and rollback

Build and test before installation:

```console
make build
make test
make lint
```

The source-tree installer is development-only and requires an explicit opt-in:

```console
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  SHUDO_UNSAFE_LOCAL_INSTALL=1 SHUDO_REPO_ROOT="$PWD" \
  ./deploy/systemd/install-local.sh
```

Production packages should install verified, root-owned binaries atomically rather than executing an installer from a user-writable checkout. Before updating, back up SQLite state and retain the previous `shudod` binary. After updating, verify the service, socket ownership, pending docket, and absence of TCP listeners.

Interrupted `EXECUTING` records become `FAILED` with a daemon-restart signal. An approved request that had not begun may be recovered only after expiry, hash, policy, working-directory, interpreter, and executable checks pass again.

## Incident response

If unauthorized execution or daemon compromise is suspected:

```console
systemctl stop shudod
systemctl mask shudod
```

Then:

1. Preserve `/var/lib/shudo`, the installed binaries, configuration, policy, and journal.
2. Remove affected accounts from the `shudo` group and terminate their sessions.
3. Inspect approved commands, output, persistence, sudo configuration, SSH keys, services, timers, cron, containers, and package changes.
4. Compare installed binary hashes with trusted build artifacts.
5. Rebuild the host from trusted media if root compromise is plausible.

Stopping Shudo removes this approval path but cannot undo a command that already ran or terminate persistence created by an approved root operation.
