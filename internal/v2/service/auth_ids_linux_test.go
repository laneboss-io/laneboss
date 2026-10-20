//go:build linux

package service

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestAuthStartIDs(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	left, right := os.NewFile(uintptr(pair[0]), "trace-peer"), os.NewFile(uintptr(pair[1]), "trace-client")
	defer right.Close()
	conn, err := net.FileConn(left)
	left.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := api.LifeRef{LifeID: fixtureID(t), Run: 3}
	binding := api.InstalledBinding{Class: api.EndpointLane, LaunchID: fixtureID(t), Target: &target}
	connection, err := newConnection(conn, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	old := os.Stderr
	os.Stderr = write
	defer func() { os.Stderr = old; write.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := fixtureID(t)
	fixtureServer(t).journalAuthenticationStart(ctx, connection, request)
	os.Stderr = old
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Event      string        `json:"event"`
		Life       api.ID        `json:"life_id"`
		Run        api.RunNumber `json:"run"`
		Launch     api.ID        `json:"launch_id"`
		Request    api.ID        `json:"request_id"`
		Connection api.ID        `json:"connection_id"`
		PID        int           `json:"peer_pid"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Event != "authentication_start" || entry.Life != target.LifeID || entry.Run != target.Run || entry.Launch != binding.LaunchID ||
		entry.Request != request || entry.Connection != connection.ID() || entry.PID != os.Getpid() {
		t.Fatal("authentication journal cannot join the lane and native worker", entry)
	}
}
