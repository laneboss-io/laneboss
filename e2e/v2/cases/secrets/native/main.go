// Native observation helper for the disposable secrets suite. Input metadata
// uses stdin; key readers are already-open protected descriptors, never argv.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
)

type input struct {
	Mode       string            `json:"mode"`
	Config     string            `json:"config"`
	Directory  string            `json:"directory"`
	Key        api.ID            `json:"key_handle"`
	KeyFD      int               `json:"key_fd"`
	RecoveryFD int               `json:"recovery_fd"`
	BackupFD   int               `json:"backup_fd"`
	Grants     []api.SecretGrant `json:"grants"`
	Profiles   []api.ID          `json:"profiles"`
	Slots      []api.ID          `json:"slots"`
}

type result struct {
	Mode     string            `json:"mode"`
	Config   string            `json:"config"`
	Key      api.ID            `json:"key_handle"`
	Digests  map[api.ID]string `json:"digests"`
	Profiles []profile         `json:"profiles"`
	Slots    []slot            `json:"slots"`
	Backup   []byte            `json:"backup,omitempty"`
	Error    *api.Error        `json:"error,omitempty"`
}

type profile struct {
	ID, LoginID, SlotID, RefreshSlotID api.ID
	Generation                         api.Generation
	Runtime                            api.Executable
	Source                             api.SecretGrant
	RefreshLocked                      bool
	Mode                               string
	LoginPresent                       bool
}

type slot struct {
	ID, ProfileID, LoginID, ProfileGrantID, ProjectionID api.ID
	Target                                               api.LifeRef
	Released                                             bool
	MaterialSHA                                          string
}

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func descriptor(fd int) (*os.File, error) {
	if fd < 3 {
		return nil, errors.New("protected descriptor is missing")
	}
	file := os.NewFile(uintptr(fd), "protected-native-input")
	if file == nil {
		return nil, errors.New("protected descriptor is invalid")
	}
	return file, nil
}

func observe(ctx context.Context, in input) (out result, resultErr error) {
	out = result{Mode: in.Mode, Config: in.Config, Key: in.Key, Digests: map[api.ID]string{}, Profiles: []profile{}, Slots: []slot{}}
	backend, err := native.New(native.Dependencies{Config: in.Config, Directory: in.Directory, KeyHandle: in.Key, Clock: realClock{}})
	if err != nil {
		return out, err
	}
	defer func() { resultErr = errors.Join(resultErr, backend.Close()) }()
	if in.Mode == "recover" {
		backup, err := descriptor(in.BackupFD)
		if err != nil {
			return out, err
		}
		defer backup.Close()
		key, err := descriptor(in.RecoveryFD)
		if err != nil {
			return out, err
		}
		defer key.Close()
		if err := backend.Recover(ctx, backup, key); err != nil {
			return out, err
		}
	} else if in.Mode != "locked" {
		key, err := descriptor(in.KeyFD)
		if err != nil {
			return out, err
		}
		defer key.Close()
		if err := backend.Unlock(ctx, in.Key, key); err != nil {
			return out, err
		}
	}
	if in.Mode == "backup" {
		key, err := descriptor(in.RecoveryFD)
		if err != nil {
			return out, err
		}
		defer key.Close()
		out.Backup, err = backend.SealRecovery(ctx, in.Key, key)
		return out, err
	}
	if in.Mode != "locked" && in.Mode != "recover" && in.Mode != "journal" {
		return out, errors.New("unknown native observation mode")
	}
	for _, grant := range in.Grants {
		material, err := backend.Fetch(ctx, grant)
		if err != nil {
			clear(material.Bytes)
			return out, err
		}
		out.Digests[grant.SourceHandle] = hash(material.Bytes)
		clear(material.Bytes)
	}
	if in.Mode == "journal" {
		err = backend.WithBroker(ctx, func(j bstate.Journal) error {
			for _, id := range in.Profiles {
				var enrolled bstate.Profile
				if err := j.Read("profile", id, &enrolled); err != nil {
					return err
				}
				if enrolled.Config != in.Config || enrolled.ID != id {
					return errors.New("native enrolled profile binding differs")
				}
				row := profile{ID: id, LoginID: enrolled.LoginID, Generation: enrolled.Generation,
					Runtime: enrolled.Runtime, Source: enrolled.Source, Mode: enrolled.Mode}
				var owner bstate.Login
				if err := j.Read("login", enrolled.LoginID, &owner); err != nil {
					var typed *api.Error
					if errors.As(err, &typed) && typed.Code == api.CodeNotFound &&
						(enrolled.Mode == "claudock-headless" || enrolled.Mode == "headless_token" || enrolled.Mode == "helper") {
						out.Profiles = append(out.Profiles, row)
						continue
					}
					return err
				}
				defer clear(owner.Material)
				row.LoginPresent, row.SlotID, row.RefreshSlotID = true, owner.SlotID, owner.RefreshSlotID
				lease, err := j.AcquireRefreshLease(enrolled.LoginID)
				if err != nil {
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeConflict {
						return err
					}
					row.RefreshLocked = true
				} else if err := lease.Close(); err != nil {
					return err
				}
				out.Profiles = append(out.Profiles, row)
			}
			for _, id := range in.Slots {
				var enrolled bstate.Slot
				if err := j.Read("slot", id, &enrolled); err != nil {
					return err
				}
				defer clear(enrolled.Material)
				defer clear(enrolled.Returned)
				if enrolled.Config != in.Config || enrolled.ID != id {
					return errors.New("native slot binding differs")
				}
				out.Slots = append(out.Slots, slot{ID: id, ProfileID: enrolled.ProfileID, LoginID: enrolled.LoginID,
					ProfileGrantID: enrolled.Credential.ProfileGrantID, ProjectionID: enrolled.ProjectionID,
					Target: enrolled.Target, Released: enrolled.Released, MaterialSHA: hash(enrolled.Material)})
			}
			return nil
		})
	}
	return out, err
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
	var in input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || len(raw) > 1<<20 || decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		fmt.Fprintln(os.Stderr, "native observation input refused")
		os.Exit(1)
	}
	out, err := observe(context.Background(), in)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) {
			out.Error = typed
		} else {
			out.Error = &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-case-secrets", Message: "native observation refused"}
		}
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
