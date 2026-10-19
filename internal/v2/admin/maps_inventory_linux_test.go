//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-map-reference-canary" {
		count, err := strconv.Atoi(os.Args[2])
		if err != nil || count < 1 || count > 8192 || mapReferenceCanary(count) != nil {
			os.Exit(61)
		}
		os.Exit(0)
	}
}

// Parser evidence, independent of the separate real-kernel maps canary above:
// a pathname can span reader buffers without changing the five native fields.
func TestMappedReferenceLongRecord(t *testing.T) {
	file, err := os.CreateTemp(privateTestDir(t), "map-record-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil {
		t.Fatal("cannot observe parser control inode")
	}
	header := fmt.Sprintf("1000-2000 r--p 00000000 %x:%x %d ", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)), stat.Ino)
	data := header + strings.Repeat("p", 4<<20) + "\n" + header + "short\n"
	if n, err := file.WriteString(data); err != nil || n != len(data) {
		t.Fatal("cannot retain long parser input", err)
	}
	refs, err := mappedReferences(context.Background(), file.Name(), map[storageInode]bool{{Device: uint64(stat.Dev), Inode: stat.Ino}: true})
	if err != nil || refs != 2 {
		t.Fatal("memory-map pathname length changed its native identity inventory", err)
	}
}

func mapReferenceCanary(count int) error {
	input, ready, hold := os.NewFile(3, "mapped-input"), os.NewFile(4, "mapped-ready"), os.NewFile(5, "mapped-hold")
	defer input.Close()
	defer hold.Close()
	mappings := make([][]byte, 0, count)
	for range count {
		data, err := unix.Mmap(int(input.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			return err
		}
		mappings = append(mappings, data)
	}
	if n, err := ready.Write([]byte{1}); err != nil || n != 1 {
		return io.ErrShortWrite
	}
	if err := ready.Close(); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, hold); err != nil {
		return err
	}
	for _, mapping := range mappings {
		if err := unix.Munmap(mapping); err != nil {
			return err
		}
	}
	return nil
}

func TestMappedReferencesLargeInventory(t *testing.T) {
	for _, count := range []int{16, 4500} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			directory := privateTestDir(t)
			for range 6 {
				directory = filepath.Join(directory, strings.Repeat("m", 180))
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			file, err := os.OpenFile(filepath.Join(directory, "mapped"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Truncate(int64(os.Getpagesize())); err != nil {
				t.Fatal(err)
			}
			var stat unix.Stat_t
			if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
				t.Fatal(err)
			}
			unmapped, err := os.CreateTemp(privateTestDir(t), "unmapped-target-")
			if err != nil {
				t.Fatal(err)
			}
			defer unmapped.Close()
			var other unix.Stat_t
			if unix.Fstat(int(unmapped.Fd()), &other) != nil || other.Dev == stat.Dev && other.Ino == stat.Ino {
				t.Fatal("unmapped control did not select an independent native inode")
			}
			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyRead.Close()
			defer readyWrite.Close()
			holdRead, holdWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer holdRead.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			t.Cleanup(cancel)
			command := exec.CommandContext(ctx, "/proc/self/exe", "admin-map-reference-canary", strconv.Itoa(count))
			command.Env, command.ExtraFiles = []string{}, []*os.File{file, readyWrite, holdRead}
			if err := command.Start(); err != nil {
				holdWrite.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := holdWrite.Close(); err != nil {
					t.Error(err)
				}
				if err := command.Wait(); err != nil {
					t.Error("native mapping canary did not complete", err)
				}
			})
			if err := readyWrite.Close(); err != nil {
				t.Fatal(err)
			}
			if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var signal [1]byte
			if _, err := io.ReadFull(readyRead, signal[:]); err != nil || signal[0] != 1 {
				t.Fatal("native mappings were not established", err)
			}
			name := "/proc/" + strconv.Itoa(command.Process.Pid) + "/maps"
			maps, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			size, readErr := io.Copy(io.Discard, maps)
			if err := errors.Join(readErr, maps.Close()); err != nil || count == 4500 && size <= 4<<20 {
				t.Fatal("large native maps did not cross the former whole-file bound", err)
			}
			unrelated, err := mappedReferences(ctx, name, map[storageInode]bool{{Device: uint64(other.Dev), Inode: other.Ino}: true})
			if err != nil || unrelated != 0 {
				t.Fatalf("unrelated native maps blocked an unmapped inode: bytes=%d refs=%d error=%v", size, unrelated, err)
			}
			actual, err := mappedReferences(ctx, name, map[storageInode]bool{{Device: uint64(stat.Dev), Inode: stat.Ino}: true})
			if err != nil || actual != uint64(count) {
				t.Fatalf("native memory map inventory lost real references: bytes=%d refs=%d error=%v", size, actual, err)
			}
			t.Logf("native maps bytes=%d references=%d", size, actual)
		})
	}
}
