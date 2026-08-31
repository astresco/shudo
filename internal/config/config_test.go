package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validConfig(extra string) string {
	return `version: 1
socketPath: /run/shudo/shudo.sock
databasePath: /var/lib/shudo/shudo.db
policyPath: /etc/shudo/policy.yaml
requirePeerCredentials: true
allowNonRoot: false
maxPendingPerUid: 8
maxPendingTotal: 256
maxExecutionSeconds: 3600
output:
  liveBytes: 1024
  persistedBytes: 2048
` + extra
}

func TestLoadDaemonValidAndDefaults(t *testing.T) {
	config, err := LoadDaemon(writeConfig(t, "version: 1\nrequirePeerCredentials: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if config.SocketPath != "/run/shudo/shudo.sock" || config.Output.LiveBytes != 1_048_576 || config.MaxPendingPerUID != 8 {
		t.Fatalf("defaults not applied: %#v", config)
	}

	config, err = LoadDaemon(writeConfig(t, validConfig("allowedEnvironment: []\nhostId: ignored-legacy\n")))
	if err != nil || len(config.AllowedEnvironment) != 0 || config.HostID != "ignored-legacy" {
		t.Fatalf("valid config rejected: %#v %v", config, err)
	}
}

func TestLoadDaemonRejectsInvalidConfiguration(t *testing.T) {
	cases := map[string]string{
		"unknown field":        validConfig("unexpected: true\n"),
		"malformed yaml":       "version: [\n",
		"wrong version":        strings.Replace(validConfig(""), "version: 1", "version: 2", 1),
		"peer credentials off": strings.Replace(validConfig(""), "requirePeerCredentials: true", "requirePeerCredentials: false", 1),
		"non-root enabled":     strings.Replace(validConfig(""), "allowNonRoot: false", "allowNonRoot: true", 1),
		"relative socket":      strings.Replace(validConfig(""), "/run/shudo/shudo.sock", "relative.sock", 1),
		"nul policy":           strings.Replace(validConfig(""), "/etc/shudo/policy.yaml", `"/etc/shudo/\0policy"`, 1),
		"live over persisted":  strings.Replace(validConfig(""), "liveBytes: 1024", "liveBytes: 4096", 1),
		"zero output":          strings.Replace(validConfig(""), "liveBytes: 1024", "liveBytes: 0", 1),
		"oversized output":     strings.Replace(validConfig(""), "persistedBytes: 2048", fmt.Sprintf("persistedBytes: %d", 101*1024*1024), 1),
		"zero per uid":         strings.Replace(validConfig(""), "maxPendingPerUid: 8", "maxPendingPerUid: 0", 1),
		"total below per uid":  strings.Replace(validConfig(""), "maxPendingTotal: 256", "maxPendingTotal: 4", 1),
		"execution too large":  strings.Replace(validConfig(""), "maxExecutionSeconds: 3600", "maxExecutionSeconds: 86401", 1),
		"environment override": validConfig("allowedEnvironment: [TERM]\n"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadDaemon(writeConfig(t, body)); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
	if _, err := LoadDaemon(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing configuration was accepted")
	}
}
