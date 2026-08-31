//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnsafeSharedDirectoriesAreRejected(t *testing.T) {
	if err := prepareSocket("/tmp/shudo.sock", uint32(os.Getgid())); err == nil {
		t.Fatal("shared /tmp accepted as the socket directory")
	}
	if err := prepareDatabase("/tmp/shudo.db"); err == nil {
		t.Fatal("shared /tmp accepted as the database directory")
	}
}

func TestDedicatedStateDirectoriesAreAccepted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require a root test process")
	}
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(databaseDirectory, "state.db")
	if err := prepareDatabase(database); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(database, []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareDatabase(database); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(database, 0644); err != nil {
		t.Fatal(err)
	}
	if err := prepareDatabase(database); err == nil {
		t.Fatal("readable database file was accepted")
	}

	socketDirectory := t.TempDir()
	if err := os.Chmod(socketDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocket(filepath.Join(socketDirectory, "shudo.sock"), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
}

func TestWritableParentCannotCreateStateDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require a root test process")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := prepareDatabase(filepath.Join(parent, "database", "state.db")); err == nil {
		t.Fatal("database directory was created beneath a writable parent")
	}
	if err := prepareSocket(filepath.Join(parent, "socket", "shudo.sock"), uint32(os.Getgid())); err == nil {
		t.Fatal("socket directory was created beneath a writable parent")
	}
}

func TestRootConfigurationFileValidation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks require a root test process")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRootFile(path); err != nil {
		t.Fatalf("secure configuration rejected: %v", err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	if err := verifyRootFile(path); err == nil {
		t.Fatal("group-writable configuration accepted")
	}
	if err := verifyRootFile("relative.yaml"); err == nil {
		t.Fatal("relative configuration accepted")
	}
}
