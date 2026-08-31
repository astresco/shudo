package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Daemon struct {
	Version int `yaml:"version"`
	// Deprecated remote fields are accepted only so an installed daemon can
	// migrate without briefly becoming unstartable. They are never used.
	HostID                 string `yaml:"hostId"`
	GRPCAddress            string `yaml:"grpcAddress"`
	GRPCServerName         string `yaml:"grpcServerName"`
	SocketPath             string `yaml:"socketPath"`
	SocketGID              uint32 `yaml:"socketGid"`
	DatabasePath           string `yaml:"databasePath"`
	PolicyPath             string `yaml:"policyPath"`
	IdentityDirectory      string `yaml:"identityDirectory"`
	RequirePeerCredentials bool   `yaml:"requirePeerCredentials"`
	AllowNonRoot           bool   `yaml:"allowNonRoot"`
	// AllowedEnvironment is retained so legacy configuration fails with a
	// specific error instead of silently ignoring an old privilege surface.
	AllowedEnvironment      []string `yaml:"allowedEnvironment"`
	MaxPendingPerUID        int      `yaml:"maxPendingPerUid"`
	MaxPendingTotal         int      `yaml:"maxPendingTotal"`
	MaxConcurrentPerUID     int      `yaml:"maxConcurrentSubmissionsPerUid"`
	MaxConcurrentTotal      int      `yaml:"maxConcurrentSubmissionsTotal"`
	MaxSubmissionsPerMinute int      `yaml:"maxSubmissionsPerMinute"`
	MaxWatchersPerUID       int      `yaml:"maxWatchersPerUid"`
	MaxWatchersPerRequest   int      `yaml:"maxWatchersPerRequest"`
	MaxExecutableBytes      int64    `yaml:"maxExecutableBytes"`
	MaxDatabaseBytes        int64    `yaml:"maxDatabaseBytes"`
	RetentionDays           int      `yaml:"retentionDays"`
	MaxRetainedUnapproved   int      `yaml:"maxRetainedUnapproved"`
	MaxExecutionSeconds     int      `yaml:"maxExecutionSeconds"`
	Output                  Output   `yaml:"output"`
}

type Output struct {
	LiveBytes      int64 `yaml:"liveBytes"`
	PersistedBytes int64 `yaml:"persistedBytes"`
}

func LoadDaemon(path string) (Daemon, error) {
	config := Daemon{
		SocketPath: "/run/shudo/shudo.sock", DatabasePath: "/var/lib/shudo/shudo.db",
		PolicyPath:              "/etc/shudo/policy.yaml",
		RequirePeerCredentials:  true,
		AllowedEnvironment:      []string{},
		MaxPendingPerUID:        8,
		MaxPendingTotal:         256,
		MaxConcurrentPerUID:     2,
		MaxConcurrentTotal:      32,
		MaxSubmissionsPerMinute: 60,
		MaxWatchersPerUID:       8,
		MaxWatchersPerRequest:   4,
		MaxExecutableBytes:      256 * 1024 * 1024,
		MaxDatabaseBytes:        1024 * 1024 * 1024,
		RetentionDays:           30,
		MaxRetainedUnapproved:   10_000,
		MaxExecutionSeconds:     3600,
		Output:                  Output{LiveBytes: 1_048_576, PersistedBytes: 10_485_760},
	}
	file, err := os.Open(path)
	if err != nil {
		return Daemon{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Daemon{}, err
	}
	if config.Version != 1 {
		return Daemon{}, errors.New("unsupported daemon configuration version")
	}
	if !config.RequirePeerCredentials || config.AllowNonRoot {
		return Daemon{}, errors.New("peer credentials must be required and allowNonRoot must be false")
	}
	for label, value := range map[string]string{
		"socketPath": config.SocketPath, "databasePath": config.DatabasePath,
		"policyPath": config.PolicyPath,
	} {
		if !filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
			return Daemon{}, fmt.Errorf("%s must be an absolute path", label)
		}
	}
	if config.Output.LiveBytes <= 0 || config.Output.PersistedBytes <= 0 ||
		config.Output.LiveBytes > config.Output.PersistedBytes || config.Output.PersistedBytes > 100*1024*1024 {
		return Daemon{}, errors.New("invalid output limits")
	}
	if config.MaxPendingPerUID < 1 || config.MaxPendingPerUID > 1_000 ||
		config.MaxPendingTotal < config.MaxPendingPerUID || config.MaxPendingTotal > 100_000 ||
		config.MaxConcurrentPerUID < 1 || config.MaxConcurrentPerUID > 64 ||
		config.MaxConcurrentTotal < config.MaxConcurrentPerUID || config.MaxConcurrentTotal > 1_024 ||
		config.MaxSubmissionsPerMinute < 1 || config.MaxSubmissionsPerMinute > 10_000 ||
		config.MaxWatchersPerUID < 1 || config.MaxWatchersPerUID > 1_000 ||
		config.MaxWatchersPerRequest < 1 || config.MaxWatchersPerRequest > config.MaxWatchersPerUID ||
		config.MaxExecutableBytes < 1024*1024 || config.MaxExecutableBytes > 4*1024*1024*1024 ||
		config.MaxDatabaseBytes < 16*1024*1024 || config.MaxDatabaseBytes > 1024*1024*1024*1024 ||
		config.RetentionDays < 1 || config.RetentionDays > 3650 ||
		config.MaxRetainedUnapproved < 100 || config.MaxRetainedUnapproved > 1_000_000 ||
		config.MaxExecutionSeconds < 1 || config.MaxExecutionSeconds > 86_400 {
		return Daemon{}, errors.New("invalid admission or execution limits")
	}
	if len(config.AllowedEnvironment) != 0 {
		return Daemon{}, errors.New("environment overrides are no longer supported; allowedEnvironment must be empty")
	}
	return config, nil
}
