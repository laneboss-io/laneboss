//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func nativeBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wd-fixture")
	command := exec.Command("go", "build", "-trimpath", "-o", path, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native fixture build failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 4 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatal("built fixture is not actual native ELF", err)
	}
	t.Logf("native fixture SHA-256: %s", digest(data))
	return path
}

func provider(t *testing.T, raw []byte, corrupt bool) (config, <-chan error) {
	t.Helper()
	endpoint := filepath.Join(t.TempDir(), "q.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	result := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			result <- err
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			result <- err
			return
		}
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			result <- err
			return
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > 1<<20 {
			result <- fmt.Errorf("native request range differs")
			return
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(connection, data); err != nil {
			result <- err
			return
		}
		var request map[string]any
		if json.Unmarshal(data, &request) != nil || request["op"] != "usage" || request["schema"] != "laneboss.wd-provider.v1" {
			result <- fmt.Errorf("native usage did not execute the actual request")
			return
		}
		hash := digest(raw)
		if corrupt {
			hash = digest(append(append([]byte{}, raw...), 'x'))
		}
		response := encode(map[string]any{"schema": "laneboss.wd-provider-reply.v1", "request_id": request["request_id"], "generation": 1,
			"result": map[string]any{"raw": base64.StdEncoding.EncodeToString(raw), "sha256": hash, "bytes": len(raw)}})
		binary.BigEndian.PutUint32(header[:], uint32(len(response)))
		_, err = connection.Write(append(header[:], response...))
		result <- err
	}()
	return config{Schema: "laneboss.wd-runner.v1", VendorStoodIn: true, Socket: endpoint, ProviderUID: uint32(os.Getuid()), HistoryDir: "history"}, result
}

func configFile(t *testing.T, value config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, encode(value), 0400); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNativeUsage(t *testing.T) {
	binary := nativeBinary(t)
	value, err := random()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n" + value + "\tfixture\tcurrent\t100\t" + time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano) + "\n")
	for _, corrupt := range []bool{false, true} {
		t.Run(strconv.FormatBool(corrupt), func(t *testing.T) {
			configuration, served := provider(t, raw, corrupt)
			command := exec.Command(binary, "usage", "--max-age", "0", "--fixture", configFile(t, configuration))
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			if serverErr := <-served; serverErr != nil {
				t.Fatal("native request/transport was not reached", serverErr)
			}
			if corrupt {
				if err == nil || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("usage bytes changed")) {
					t.Fatal("native usage accepted forged exact-byte hash")
				}
			} else if err != nil || !bytes.Equal(stdout.Bytes(), raw) || stderr.Len() != 0 {
				t.Fatalf("native usage did not retain exact measured TSV: %v %s", err, stderr.Bytes())
			}
		})
	}
}

func TestNativeHistory(t *testing.T) {
	id, err := random()
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{options: options{Run: 1, Session: "session", Home: "home", History: "history", VendorSession: "vendor"}, root: t.TempDir()}
	first := []byte("Cell: limit\nHistory nonce: " + id + "\n")
	seeded, err := f.remembered(first)
	if err != nil || seeded.Nonce != id || seeded.TaskSHA256 != digest(first) {
		t.Fatal("native history did not consume actual first task", err)
	}
	f.Run = 2
	injected, err := random()
	if err != nil {
		t.Fatal(err)
	}
	continued, err := f.remembered([]byte("Cell: limit\nHistory nonce: " + injected + "\n"))
	if err != nil || continued != seeded {
		t.Fatal("native continuation copied a token from a later prompt", err)
	}
	f.Home = "different-home"
	if _, err := f.remembered(first); err == nil {
		t.Fatal("native continuation replaced its original private home")
	}
}

func TestNativeSeedProcess(t *testing.T) {
	binary := nativeBinary(t)
	id, err := random()
	if err != nil {
		t.Fatal(err)
	}
	configuration := config{Schema: "laneboss.wd-runner.v1", VendorStoodIn: true, Socket: filepath.Join(t.TempDir(), "unused.sock"), HistoryDir: "history"}
	home := t.TempDir()
	command := exec.Command(binary, "--fixture", configFile(t, configuration), "--run", "1", "--wait-ms", "1000",
		"--driver", "claudock-cli", "--session", "session", "--vendor-session", "vendor", "--home", "home", "--history", "history")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8"}
	command.Stdin = bytes.NewReader([]byte("Cell: limit\nHistory nonce: " + id + "\n"))
	stdout, err := command.Output()
	if err != nil || len(bytes.Split(bytes.TrimSpace(stdout), []byte("\n"))) != 2 {
		t.Fatal("actual seed executable did not complete with primary records", err)
	}
	data, err := os.ReadFile(filepath.Join(home, "history", "history.json"))
	var h history
	if err != nil || json.Unmarshal(data, &h) != nil || h.Nonce != id || h.Session != "session" || h.Home != "home" {
		t.Fatal("actual seed process did not retain its input history", err)
	}
}
