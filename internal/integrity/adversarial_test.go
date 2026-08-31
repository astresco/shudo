//go:build linux

package integrity

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdversarialEnvironmentCannotBeAllowlisted(t *testing.T) {
	for _, key := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "NODE_OPTIONS", "BASH_ENV", "TERM"} {
		t.Run(key, func(t *testing.T) {
			if _, err := SanitizeEnvironment(map[string]string{key: "attacker-controlled"}, []string{key}); err == nil {
				t.Fatalf("dangerous variable %s bypassed the local allowlist", key)
			}
		})
	}

	t.Setenv("SHUDO_PARENT_SECRET", "must-not-reach-root-command")
	environment, err := SanitizeEnvironment(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "SHUDO_PARENT_SECRET") {
		t.Fatalf("daemon environment leaked into execution: %q", joined)
	}
	for _, required := range []string{"PATH=" + safePath, "HOME=/root", "LANG=C.UTF-8"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sanitized environment omitted %q: %q", required, joined)
		}
	}
}

func TestAdversarialVerifiedDescriptorSurvivesPathReplacement(t *testing.T) {
	directory := t.TempDir()
	approvedPath := filepath.Join(directory, "approved-tool")
	copyTestExecutable(t, "/usr/bin/true", approvedPath)
	metadata, err := InspectExecutable(approvedPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := OpenVerifiedExecutable(metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()

	replacement := filepath.Join(directory, "replacement")
	copyTestExecutable(t, "/usr/bin/touch", replacement)
	if err := os.Rename(replacement, approvedPath); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(directory, "replacement-executed")
	command := exec.Command(os.Args[0], "-test.run=TestExecVerifiedHelper")
	command.Env = append(os.Environ(), "SHUDO_TEST_EXEC_MODE=pinned-original", "SHUDO_TEST_MARKER="+marker)
	command.ExtraFiles = []*os.File{verified}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("verified descriptor execution failed: %v: %s", err, output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("replacement executable ran through pathname: %v", err)
	}
	if err := VerifyExecutable(metadata); err == nil {
		t.Fatal("replaced pathname still matched approved metadata")
	}
}

func TestAdversarialSymlinkCannotBeInspectedAsExecutable(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(directory, "attacker-link")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectExecutable(link); err == nil {
		t.Fatal("O_NOFOLLOW boundary accepted a symlink executable")
	}
}

func copyTestExecutable(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0755); err != nil {
		t.Fatal(err)
	}
}
