package box

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/boxaws"
	"laneboss.io/laneboss/internal/boxcfg"
	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
	"laneboss.io/laneboss/internal/boxgcp"
	"laneboss.io/laneboss/internal/boxguest"
	"laneboss.io/laneboss/internal/boxledger"
	"laneboss.io/laneboss/internal/boxrun"
	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/testenv"
)

type environment struct {
	getenv     func(string) string
	userHome   string
	homeErr    error
	now        func() time.Time
	signals    <-chan os.Signal
	exit       func(int)
	locate     func(boxcfg.LocateOptions) (string, error)
	load       func(string, boxcfg.Env) (*boxcore.Config, error)
	openLedger func(*boxcore.Config, io.Writer) (boxcore.Ledger, error)
	archiveRun boxexec.Runner
}

type buildDeps struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	env            environment
	ledger         boxcore.Ledger
}

type builder func(*boxcore.Config, buildDeps) (boxcore.Service, error)

func (e environment) defaults() environment {
	if e.getenv == nil {
		e.getenv = os.Getenv
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.exit == nil {
		e.exit = os.Exit
	}
	if e.load == nil {
		e.load = boxcfg.Load
	}
	if e.locate == nil {
		e.locate = boxcfg.Locate
	}
	if e.openLedger == nil {
		e.openLedger = openLedger
	}
	if e.archiveRun == nil {
		e.archiveRun = boxexec.ExecRunner{}
	}
	return e
}

func openLedger(cfg *boxcore.Config, notes io.Writer) (boxcore.Ledger, error) {
	l, err := boxledger.Open(cfg.Ledger.Path, cfg.Ledger.Schema)
	if err != nil {
		return nil, err
	}
	l.SetNotes(notes)
	return l, nil
}

func buildService(cfg *boxcore.Config, d buildDeps) (boxcore.Service, error) {
	l := d.ledger
	if l == nil {
		var err error
		l, err = d.env.openLedger(cfg, d.stderr)
		if err != nil {
			return nil, errors.New("the ledger cannot be opened")
		}
	}
	runner := boxexec.ExecRunner{}
	providers := make(map[string]boxcore.Provider)
	if cfg.AWS != nil {
		providers["aws"] = boxaws.New(*cfg.AWS, runner, boxaws.Options{
			Org: cfg.Org, NamePrefix: cfg.Defaults.NamePrefix,
			Getenv: d.env.getenv, Now: d.env.now, Sleep: sleep,
		})
	}
	if cfg.GCP != nil {
		providers["gcp"] = boxgcp.New(*cfg.GCP, runner, boxgcp.Options{
			Org: cfg.Org, NamePrefix: cfg.Defaults.NamePrefix,
			Getenv: d.env.getenv, Now: d.env.now, Sleep: sleep,
		})
	}
	return boxrun.New(boxcore.Deps{
		Config: cfg, Providers: providers, Ledger: l, Guest: boxguest.New(),
		Now: d.env.now, Sleep: sleep,
		NewRunID: func() string {
			id, err := boxcore.NewRunID(d.env.now(), rand.Reader)
			if err != nil {
				panic("box: the run id cannot be created")
			}
			return id
		},
		Out: d.stdout, Err: d.stderr, Version: identity.Version,
		SelfSHA: executableSHA(),
	}), nil
}

func sleep(ctx context.Context, d time.Duration) error {
	// Instrumentation builds only: black-box rows shorten the polling sleeps with this scale.
	if scale, ok := testenv.BoxSleepScale(); ok {
		d = time.Duration(float64(d) * scale)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func executableSHA() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, f)
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func withSignals(e environment, stderr io.Writer) (context.Context, func()) {
	var ctx context.Context
	var cancel context.CancelFunc
	ch := e.signals
	var owned chan os.Signal
	if ch == nil {
		owned = make(chan os.Signal, 2)
		signal.Notify(owned, os.Interrupt, syscall.SIGTERM)
		ch = owned
		ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		count := 0
		for {
			select {
			case <-done:
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
				count++
				if count == 1 {
					cancel()
					continue
				}
				fmt.Fprintln(stderr, "laneboss box: second signal, leaving now")
				e.exit(130)
				return
			}
		}
	}()
	return ctx, func() {
		close(done)
		if owned != nil {
			signal.Stop(owned)
		}
		cancel()
		<-finished
	}
}
