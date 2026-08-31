# Shudo

Shudo (“superhumanuser do”) is a local, human-in-the-loop privilege broker for agents and other unprivileged processes. It gives an agent a way to request one exact root operation without giving that agent a password, sudo timestamp, private key, token, or reusable root capability.

There is no central server, web application, host enrollment, TCP listener, or remote execution protocol. Everything happens on one Linux machine:

```text
agent session                       separate root session
      |                                      |
      | submit + watch                       | inspect + decide
      v                                      v
             /run/shudo/shudo.sock
                        |
                        v
                    shudod (root)
                        |
                        v
                  exact approved argv
```

## Normal use

In the agent session:

```console
$ shudo --reason "Install jq for the build" apt-get install -y jq
```

Shudo is quiet while waiting and then behaves like the command: it streams stdout/stderr and returns the command's exit code. Use `--verbose` to show request lifecycle text, `--detach` to print the request ID and return, or `--json` for machine-readable events. A reason is always required; on an interactive terminal Shudo prompts when `--reason` is omitted.

In a separate session that is already root:

```console
# shudo --pending
# shudo --approve                     # numbered interactive picker
```

`shudo --pending` displays short request IDs. A unique prefix is accepted by `--show`, `--approve`, and `--deny`, while omitting it opens a numbered picker. For example, `shudo --approve b02fc4d5`. `shudo --requests` shows the 50 most recent records. All review commands require the CLI process to already be UID 0; Linux `SO_PEERCRED` enforces the same rule at the daemon.

Shudo does not invoke `sudo`. You can enter the root review session using `sudo -i`, `su`, a console, or any other mechanism you already trust. The submitter and approver may ultimately be the same human; Shudo does not impose a four-eyes rule.

## Build and install

Building requires Linux, GNU Make, and the Go toolchain declared in `go.mod`. `protoc` is needed only when changing the wire protocol. The installed binaries are static and require no language runtime or package manager.

```console
make build
make test
make adversarial
make coverage
make lint
```

Do not run a source-tree installer as root on a valuable host. Build a reviewed,
checksummed package or staging bundle as described in
[Production deployment](docs/production-deployment.md). `make install` refuses
source-tree installation. The explicitly named `make install-dev` target exists
only for disposable development hosts.

`make coverage` enforces at least 95% statement coverage across the handwritten
`internal/...` packages and writes an HTML report to `coverage/coverage.html`.
Generated protobuf sources and the thin executable composition roots are not
part of the unit-coverage denominator; `make test` and `make build` still test
and compile the complete repository. `make check` runs the tests, linter, and
coverage gate together.

`make adversarial` runs the dedicated privilege-boundary attack cases under the
Go race detector. These exercise forged peer identity, unauthorized review,
concurrent and rebound approvals, post-approval policy denial, executable and
working-directory replacement, shebang-interpreter replacement, shell
metacharacters, environment rejection, verified-descriptor pinning, resource
bounds, and append-only database protections.

For an isolated source-run daemon, run `make dev`, then use the clean-environment
launch command it prints. The Go compiler never runs as root. The resulting
development binary still executes commands as root, so use a disposable host.
Run `make tools generate` after changing the protobuf definition.

Add agent accounts to the `shudo` group, then start a new login session so group membership takes effect. Do not grant those accounts sudo access.

## Documentation

- [CLI reference](docs/cli.md)
- [Architecture](docs/architecture.md)
- [Configuration and policy](docs/configuration.md)
- [Security](docs/security.md)
- [Threat model](docs/threat-model.md)
- [Production deployment](docs/production-deployment.md)
- [Operator runbook](docs/operations.md)
- [Local end-to-end test](docs/local-end-to-end-test.md)

Read the security, threat-model, and production-deployment documents before using Shudo on a valuable host.

## Project status

This repository is the public source for Shudo. It is provided under the
[MIT License](LICENSE) as-is. The maintainer offers no support, warranty,
compatibility commitments, packaged releases, or contribution process. Users
who choose to use it are responsible for reviewing, compiling, deploying, and
operating it themselves. Pull requests and support requests are not accepted.
