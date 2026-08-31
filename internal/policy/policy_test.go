package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDenyCannotBeOverriddenByDefault(t *testing.T) {
	executable := "/usr/bin/passwd"
	path := "/etc/shudo/**"
	argv := []string{"status", "*"}
	config := Config{Version: 1, Defaults: Defaults{Action: RequireApproval}, Rules: []Rule{{Match: Match{Executable: &executable}, Action: Deny}, {Match: Match{Path: &path}, Action: Deny}, {Match: Match{Argv: &argv}, Action: RequireApproval}}}
	if got := Evaluate(config, Input{Executable: "/usr/bin/passwd", Cwd: "/tmp"}); got != Deny {
		t.Fatalf("got %s", got)
	}
	if got := Evaluate(config, Input{Executable: "/usr/bin/id", Cwd: "/etc/shudo/identity"}); got != Deny {
		t.Fatalf("path deny got %s", got)
	}
	if got := Evaluate(config, Input{Executable: "/usr/bin/systemctl", Argv: []string{"status", "nginx"}, Cwd: "/"}); got != RequireApproval {
		t.Fatalf("approval got %s", got)
	}
}

func TestDenyCannotBeShadowedByEarlierApproval(t *testing.T) {
	broad := "/usr/bin/*"
	passwd := "/usr/bin/passwd"
	config := Config{Version: 1, Defaults: Defaults{Action: RequireApproval}, Rules: []Rule{
		{Match: Match{Executable: &broad}, Action: RequireApproval},
		{Match: Match{Executable: &passwd}, Action: Deny},
	}}
	if got := Evaluate(config, Input{Executable: "/usr/bin/passwd", Cwd: "/"}); got != Deny {
		t.Fatalf("got %s", got)
	}
}

func TestApprovalRuleCanSelectFromDefaultDeny(t *testing.T) {
	executable := "/usr/bin/id"
	config := Config{Version: 1, Defaults: Defaults{Action: Deny}, Rules: []Rule{
		{Match: Match{Executable: &executable}, Action: RequireApproval},
	}}
	if got := Evaluate(config, Input{Executable: executable, Cwd: "/"}); got != RequireApproval {
		t.Fatalf("approval rule returned %s", got)
	}
	if got := Evaluate(config, Input{Executable: "/usr/bin/true", Cwd: "/"}); got != Deny {
		t.Fatalf("default deny returned %s", got)
	}
}

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPolicy(t *testing.T) {
	valid := `version: 1
defaults:
  action: require-approval
rules:
  - match:
      executable: /usr/bin/id
    action: require-approval
`
	config, err := Load(writePolicy(t, valid))
	if err != nil || len(config.Rules) != 1 {
		t.Fatalf("valid policy rejected: %#v %v", config, err)
	}
	cases := []string{
		"version: [",
		strings.Replace(valid, "version: 1", "version: 2", 1),
		strings.Replace(valid, "require-approval", "invalid", 1),
		strings.Replace(valid, "action: require-approval", "action: invalid", 1),
		strings.Replace(valid, "action: require-approval", "action: allow", 1),
		strings.Replace(valid, "    action: require-approval", "    action: allow", 1),
		valid + "unknown: true\n",
	}
	for index, body := range cases {
		if _, err := Load(writePolicy(t, body)); err == nil {
			t.Fatalf("invalid policy %d was accepted", index)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing policy was accepted")
	}

	var oversized strings.Builder
	oversized.WriteString("version: 1\ndefaults:\n  action: deny\nrules:\n")
	for index := 0; index < 10_001; index++ {
		oversized.WriteString("  - match: {}\n    action: deny\n")
	}
	if _, err := Load(writePolicy(t, oversized.String())); err == nil {
		t.Fatal("oversized policy was accepted")
	}
}

func TestMatchDimensionsAndGlobSemantics(t *testing.T) {
	executable := "/usr/bin/*"
	uid := uint32(1000)
	argv := []string{"st?tus", "**"}
	path := "/srv/**/config?.yaml"
	match := Match{Executable: &executable, RequesterUID: &uid, Argv: &argv, Path: &path}
	valid := Input{Executable: "/usr/bin/tool", UID: uid, Argv: []string{"status", "/srv/app/config1.yaml"}, Cwd: "/tmp"}
	if !matches(match, valid) {
		t.Fatal("complete match was rejected")
	}
	mutations := []Input{
		{Executable: "/sbin/tool", UID: uid, Argv: valid.Argv, Cwd: valid.Cwd},
		{Executable: valid.Executable, UID: 1001, Argv: valid.Argv, Cwd: valid.Cwd},
		{Executable: valid.Executable, UID: uid, Argv: []string{"status"}, Cwd: valid.Cwd},
		{Executable: valid.Executable, UID: uid, Argv: []string{"start", valid.Argv[1]}, Cwd: valid.Cwd},
		{Executable: valid.Executable, UID: uid, Argv: []string{"status", "relative"}, Cwd: "/tmp"},
	}
	for index, input := range mutations {
		if matches(match, input) {
			t.Fatalf("mismatch %d was accepted", index)
		}
	}
	if glob("/usr/*/id", "/usr/local/bin/id") {
		t.Fatal("single star crossed a path separator")
	}
	if !glob("/usr/**/id", "/usr/local/bin/id") || glob("file?", "file/") {
		t.Fatal("glob semantics are incorrect")
	}
	for _, action := range []string{RequireApproval, Deny} {
		if !validAction(action) {
			t.Fatalf("valid action %q rejected", action)
		}
	}
	if validAction("root-now") {
		t.Fatal("invalid action accepted")
	}
}

func TestPathMatchingCanonicalizesRelativeAndOptionValues(t *testing.T) {
	pattern := "/etc/shudo/**"
	match := Match{Path: &pattern}
	for _, input := range []Input{
		{Executable: "/usr/bin/cp", Cwd: "/tmp", Argv: []string{"source", "../etc/shudo/policy.yaml"}},
		{Executable: "/usr/bin/tool", Cwd: "/", Argv: []string{"--file=/tmp/../etc/shudo/config.yaml"}},
	} {
		if !matches(match, input) {
			t.Fatalf("canonical sensitive path did not match: %#v", input)
		}
	}
}

func TestPolicyPathsSkipsInvalidValuesAndResolvesSymlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	paths := policyPaths(Input{Executable: "/bin/true", Cwd: directory, Argv: []string{"", "bad\x00value", link}})
	if paths[len(paths)-1] != target {
		t.Fatalf("symlink was not resolved: %#v", paths)
	}
}
