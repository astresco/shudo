//go:build linux

package localcreds

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
)

// AuthInfo is derived by the daemon from Linux SO_PEERCRED. It is never
// populated from caller-controlled request data.
type AuthInfo struct {
	UID       uint32
	GID       uint32
	PID       int32
	Username  string
	GroupName string
}

func (AuthInfo) AuthType() string { return "linux-so-peercred" }

type Credentials struct{}

func New() credentials.TransportCredentials { return Credentials{} }

func (Credentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("SO_PEERCRED credentials are server-side only")
}

func (Credentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, fmt.Errorf("local broker requires a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var peer *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		peer, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, nil, err
	}
	if socketErr != nil {
		return nil, nil, socketErr
	}
	info := AuthInfo{UID: peer.Uid, GID: peer.Gid, PID: peer.Pid}
	if found, err := user.LookupId(strconv.FormatUint(uint64(peer.Uid), 10)); err == nil {
		info.Username = found.Username
	}
	if found, err := user.LookupGroupId(strconv.FormatUint(uint64(peer.Gid), 10)); err == nil {
		info.GroupName = found.Name
	}
	return conn, info, nil
}

func (Credentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "linux-so-peercred"}
}
func (Credentials) Clone() credentials.TransportCredentials { return Credentials{} }
func (Credentials) OverrideServerName(string) error         { return nil }
