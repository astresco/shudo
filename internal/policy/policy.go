package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	RequireApproval = "require-approval"
	Deny            = "deny"
)

type Config struct {
	Version  int      `yaml:"version"`
	Defaults Defaults `yaml:"defaults"`
	Rules    []Rule   `yaml:"rules"`
}

type Defaults struct {
	Action string `yaml:"action"`
}

type Rule struct {
	Match  Match  `yaml:"match"`
	Action string `yaml:"action"`
}

type Match struct {
	Executable   *string   `yaml:"executable"`
	Argv         *[]string `yaml:"argv"`
	Path         *string   `yaml:"path"`
	RequesterUID *uint32   `yaml:"requesterUid"`
}

type Input struct {
	Executable string
	Argv       []string
	Cwd        string
	UID        uint32
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if config.Version != 1 || !validAction(config.Defaults.Action) {
		return Config{}, errors.New("invalid policy version or default action")
	}
	if len(config.Rules) > 10_000 {
		return Config{}, errors.New("policy contains too many rules")
	}
	for index, rule := range config.Rules {
		if !validAction(rule.Action) {
			return Config{}, fmt.Errorf("invalid action in rule %d", index)
		}
	}
	return config, nil
}

func Evaluate(config Config, input Input) string {
	// A deny rule is a local security invariant and cannot be shadowed by an
	// earlier broad approval rule.
	for _, rule := range config.Rules {
		if rule.Action == Deny && matches(rule.Match, input) {
			return Deny
		}
	}
	for _, rule := range config.Rules {
		if rule.Action == RequireApproval && matches(rule.Match, input) {
			return RequireApproval
		}
	}
	// Every non-denied request requires a fresh local root approval. There is
	// deliberately no policy action that can execute a request automatically.
	return config.Defaults.Action
}

func matches(match Match, input Input) bool {
	if match.Executable != nil && !glob(*match.Executable, input.Executable) {
		return false
	}
	if match.RequesterUID != nil && *match.RequesterUID != input.UID {
		return false
	}
	if match.Argv != nil {
		if len(*match.Argv) != len(input.Argv) {
			return false
		}
		for index, pattern := range *match.Argv {
			if !glob(pattern, input.Argv[index]) {
				return false
			}
		}
	}
	if match.Path != nil {
		paths := policyPaths(input)
		found := false
		for _, path := range paths {
			if glob(*match.Path, path) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func glob(pattern, value string) bool {
	var expression strings.Builder
	expression.WriteByte('^')
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				expression.WriteString(".*")
				index++
			} else {
				expression.WriteString("[^/]*")
			}
		case '?':
			expression.WriteString("[^/]")
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
		}
	}
	expression.WriteByte('$')
	return regexp.MustCompile(expression.String()).MatchString(value)
}

func validAction(action string) bool {
	return action == RequireApproval || action == Deny
}

func policyPaths(input Input) []string {
	paths := []string{filepath.Clean(input.Executable), filepath.Clean(input.Cwd)}
	for _, argument := range input.Argv {
		candidates := []string{argument}
		if _, value, found := strings.Cut(argument, "="); found {
			candidates = append(candidates, value)
		}
		for _, candidate := range candidates {
			if candidate == "" || strings.ContainsRune(candidate, '\x00') {
				continue
			}
			if !filepath.IsAbs(candidate) {
				candidate = filepath.Join(input.Cwd, candidate)
			}
			candidate = filepath.Clean(candidate)
			if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
				candidate = resolved
			}
			paths = append(paths, candidate)
		}
	}
	return paths
}
