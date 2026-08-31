//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	shudov1 "shudo.local/shudo/gen/shudov1"
	"shudo.local/shudo/internal/config"
	"shudo.local/shudo/internal/daemon"
	"shudo.local/shudo/internal/integrity"
	"shudo.local/shudo/internal/localcreds"
	"shudo.local/shudo/internal/state"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "shudod:", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "__exec-fds" {
		if len(os.Args) < 6 || (os.Args[4] != "0" && os.Args[4] != "1") {
			return errors.New("invalid internal pinned execution request")
		}
		var interpreterArgument *string
		if os.Args[4] == "1" {
			interpreterArgument = &os.Args[5]
		}
		interpreterFD := -1
		if os.Args[3] != "" {
			interpreterFD = integrity.InterpreterFD
		}
		return integrity.ExecPinned(integrity.ExecutableFD, integrity.DirectoryFD, interpreterFD,
			os.Args[2], os.Args[6:], os.Environ(), os.Args[3], interpreterArgument)
	}
	if len(os.Args) > 1 && os.Args[1] == "__exec-fd" {
		if len(os.Args) < 3 {
			return errors.New("invalid internal execution request")
		}
		return integrity.ExecVerified(3, os.Args[2:], os.Environ())
	}
	flags := flag.NewFlagSet("shudod", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/shudo/config.yaml", "daemon configuration")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	_ = syscall.Umask(0077)
	if err := verifyRootFile(*configPath); err != nil {
		return fmt.Errorf("unsafe daemon configuration: %w", err)
	}
	cfg, err := config.LoadDaemon(*configPath)
	if err != nil {
		return err
	}
	if err := verifyRootFile(cfg.PolicyPath); err != nil {
		return fmt.Errorf("unsafe policy configuration: %w", err)
	}
	if err := prepareDatabase(cfg.DatabasePath); err != nil {
		return err
	}
	store, err := state.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := daemon.New(cfg, store)
	if err != nil {
		return err
	}
	service.RecoverApproved()
	if err := prepareSocket(cfg.SocketPath, cfg.SocketGID); err != nil {
		return err
	}
	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(cfg.SocketPath, 0, int(cfg.SocketGID)); err != nil {
		return err
	}
	if err := os.Chmod(cfg.SocketPath, 0660); err != nil {
		return err
	}
	server := grpc.NewServer(grpc.Creds(localcreds.New()), grpc.MaxRecvMsgSize(512*1024), grpc.MaxSendMsgSize(2*1024*1024))
	shudov1.RegisterLocalBrokerServer(server, service)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go service.RunMaintenance(ctx)
	go func() {
		<-ctx.Done()
		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			// Watch is intentionally long-lived. Force it closed so systemd can
			// restart promptly; clients resume by request ID and output sequence.
			server.Stop()
		}
	}()
	fmt.Fprintf(os.Stderr, "shudod %s listening on %s\n", daemon.Version, cfg.SocketPath)
	return server.Serve(listener)
}
func prepareSocket(path string, gid uint32) error {
	directory := filepath.Dir(path)
	if directory == "/" {
		return errors.New("socket must be inside a dedicated directory")
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if parentErr := verifyDirectoryChain(filepath.Dir(directory)); parentErr != nil {
			return errors.New("socket parent directory is unsafe")
		}
		if err := os.Mkdir(directory, 0750); err != nil {
			return err
		}
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return err
	}
	if err := verifyDirectoryChain(directory); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("socket directory must be a dedicated root-owned directory not writable by group or other")
	}
	if err := os.Chown(directory, 0, int(gid)); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0750); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to replace non-socket at " + path)
	}
	return os.Remove(path)
}

func prepareDatabase(path string) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if parentErr := verifyDirectoryChain(filepath.Dir(directory)); parentErr != nil {
			return errors.New("database parent directory is unsafe")
		}
		if err := os.Mkdir(directory, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return err
	}
	if err := verifyDirectoryChain(directory); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("database directory must be root-owned and not writable by group or other")
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		fileInfo, statErr := os.Lstat(candidate)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return statErr
		}
		fileStat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 || fileStat.Uid != 0 || fileInfo.Mode().Perm() != 0600 {
			return errors.New("database files must be root-owned regular files with mode 0600")
		}
	}
	return nil
}

// verifyDirectoryChain ensures an unprivileged process cannot replace a
// validated child path between startup checks and use. A root-owned sticky
// directory such as /tmp is safe as an ancestor because non-owners cannot
// rename root-owned children within it; the final state/socket directory is
// still required to be non-writable by group and other.
func verifyDirectoryChain(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 {
			return errors.New("directory path must contain only root-owned directories")
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("directory path contains an unsafe writable ancestor")
		}
		if current == "/" {
			return nil
		}
	}
}

func verifyRootFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}
	if err := verifyDirectoryChain(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("file must be a root-owned regular file not writable by group or other")
	}
	return nil
}

var _ credentials.TransportCredentials
