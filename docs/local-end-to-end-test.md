# Local end-to-end test

Build and install:

```console
cd /Code/Shudo
make build
make test
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  SHUDO_UNSAFE_LOCAL_INSTALL=1 SHUDO_REPO_ROOT="$PWD" \
  ./deploy/systemd/install-local.sh
newgrp shudo
```

Open terminal A as the unprivileged account:

```console
shudo --reason "Verify local approval flow" -- /usr/bin/id
```

It should wait quietly. In terminal B, become root and review the docket:

```console
sudo -i
shudo --pending
shudo --approve
```

The last command opens a numbered picker, displays the complete selected request,
and asks for confirmation. You can instead use the short ID shown by `--pending`,
such as `shudo --show b02fc4d5 --verbose` or `shudo --approve b02fc4d5`; direct
interactive approval still displays the complete request before confirmation.

Terminal A should print `uid=0(root) ...` and exit 0. Repeat with `shudo --deny REQUEST_ID`; terminal A must exit nonzero without executing. Test timeout with `--timeout 3s`; both the stored request and waiting CLI must expire.

Authorization checks:

```console
# As a non-root shudo-group member; these must fail:
shudo --pending
shudo --requests
shudo --show OWN_REQUEST_ID
shudo --approve REQUEST_ID
shudo --deny REQUEST_ID
```

Verify the daemon has only a Unix listener:

```console
systemctl status shudod --no-pager
ss -ltnp | grep shudod && echo "unexpected TCP listener"
namei -l /run/shudo/shudo.sock
```
