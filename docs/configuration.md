# Configuration

The daemon reads `/etc/shudo/config.yaml` with strict field checking. The installer derives `socketGid` from the local `shudo` group.

```yaml
version: 1
socketPath: /run/shudo/shudo.sock
socketGid: 982
databasePath: /var/lib/shudo/shudo.db
policyPath: /etc/shudo/policy.yaml
requirePeerCredentials: true
allowNonRoot: false
allowedEnvironment: []
maxPendingPerUid: 8
maxPendingTotal: 256
maxConcurrentSubmissionsPerUid: 2
maxConcurrentSubmissionsTotal: 32
maxSubmissionsPerMinute: 60
maxWatchersPerUid: 8
maxWatchersPerRequest: 4
maxExecutableBytes: 268435456
maxDatabaseBytes: 1073741824
retentionDays: 30
maxRetainedUnapproved: 10000
maxExecutionSeconds: 3600
output:
  liveBytes: 1048576
  persistedBytes: 10485760
```

`requirePeerCredentials` must be true and `allowNonRoot` must be false. The latter is retained only to make unsafe legacy configuration fail explicitly. Legacy remote fields are accepted during upgrade but ignored.

`allowedEnvironment` is retained only so upgrades fail with a specific error. It
must be empty. Root commands always receive the fixed `PATH`, `HOME=/root`, and
`LANG=C.UTF-8` baseline.

The pending, concurrency, and per-minute fields bound request admission.
Watcher limits bound replay work. `maxExecutableBytes` is checked before hashing.
`maxDatabaseBytes` reserves ten percent for decisions and SQLite bookkeeping;
large request/output writes stop before using that reserve. Hourly retention
removes unapproved terminal records older than `retentionDays` or beyond
`maxRetainedUnapproved`. Approved records remain append-only audit evidence.

Policy is read from `/etc/shudo/policy.yaml` at submission and immediately before execution:

```yaml
version: 1
defaults:
  action: require-approval
rules:
  - match:
      executable: /usr/bin/passwd
    action: deny
  - match:
      path: /etc/shudo/**
    action: deny
```

Actions are `require-approval` and `deny`. Every non-denied request waits for a
fresh local root decision; there is no automatic execution action. A legacy
policy containing `allow` is invalid and prevents the daemon from accepting
requests.

Path matching cleans absolute arguments, resolves relative arguments against
the recorded cwd, and recognizes `--option=PATH` forms. Existing symlinks are
resolved. It still cannot infer paths embedded inside shell programs, response
files, or command-specific configuration. Use executable/argv denies for those
cases, and never treat generic path matching as a command sandbox.
