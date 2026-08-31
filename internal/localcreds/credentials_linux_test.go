//go:build linux

package localcreds

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialMetadataAndUnsupportedClient(t *testing.T) {
	credentials := Credentials{}
	if (AuthInfo{}).AuthType() != "linux-so-peercred" {
		t.Fatal("unexpected auth type")
	}
	if New() == nil || credentials.Clone() == nil {
		t.Fatal("credentials constructor returned nil")
	}
	if credentials.Info().SecurityProtocol != "linux-so-peercred" {
		t.Fatal("unexpected protocol info")
	}
	if err := credentials.OverrideServerName("ignored"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := credentials.ClientHandshake(context.Background(), "", nil); err == nil {
		t.Fatal("client handshake was accepted")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, _, err := credentials.ServerHandshake(left); err == nil {
		t.Fatal("non-Unix connection was accepted")
	}
}

func TestServerHandshakeUsesKernelPeerCredentials(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := make(chan struct {
		info AuthInfo
		err  error
	}, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			result <- struct {
				info AuthInfo
				err  error
			}{err: acceptErr}
			return
		}
		defer connection.Close()
		returned, auth, handshakeErr := (Credentials{}).ServerHandshake(connection)
		if returned != connection && handshakeErr == nil {
			handshakeErr = os.ErrInvalid
		}
		info, _ := auth.(AuthInfo)
		result <- struct {
			info AuthInfo
			err  error
		}{info: info, err: handshakeErr}
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got := <-result
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.info.UID != uint32(os.Getuid()) || got.info.GID != uint32(os.Getgid()) || got.info.PID != int32(os.Getpid()) {
		t.Fatalf("wrong peer identity: %#v", got.info)
	}
}
