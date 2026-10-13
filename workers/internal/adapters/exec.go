// Package adapters invokes external providers through structured argv arrays. A shell is
// never used, so untrusted values can never be interpreted as shell syntax.
package adapters

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// RunOptions controls a single provider invocation.
type RunOptions struct {
	Timeout  time.Duration
	MaxBytes int
	Dir      string
	Env      []string
	Input    string
}

// ExecResult captures the outcome of a provider invocation.
type ExecResult struct {
	Argv      []string
	ExitCode  int
	Stdout    string
	Stderr    string
	Duration  time.Duration
	TimedOut  bool
	Truncated bool
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if l.limit <= 0 {
		return n, nil
	}
	remaining := l.limit - l.buf.Len()
	if remaining <= 0 {
		return n, nil
	}
	if len(p) > remaining {
		l.buf.Write(p[:remaining])
	} else {
		l.buf.Write(p)
	}
	return n, nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }
func (l *limitedBuffer) truncated() bool {
	return l.limit > 0 && l.buf.Len() >= l.limit
}

// Run executes argv under ctx with a bounded timeout, bounded output, and cooperative
// cancellation (SIGTERM, then SIGKILL after WaitDelay). It returns an ExecResult even for
// non-zero exits; a Go error is returned only for spawn failures.
func Run(ctx context.Context, argv []string, opts RunOptions) (ExecResult, error) {
	res := ExecResult{Argv: argv}
	if len(argv) == 0 {
		return res, errors.New("empty argv")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 16 * 1024 * 1024
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Dir = opts.Dir
	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	outLim := &limitedBuffer{limit: maxBytes}
	errLim := &limitedBuffer{limit: maxBytes}
	cmd.Stdout = outLim
	cmd.Stderr = errLim
	if opts.Input != "" {
		cmd.Stdin = bytes.NewBufferString(opts.Input)
	}
	// Cooperative cancellation: ask nicely, then force.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second

	start := time.Now()
	err := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = outLim.String()
	res.Stderr = errLim.String()
	res.Truncated = outLim.truncated() || errLim.truncated()

	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	if ctx.Err() != nil && !res.TimedOut {
		// Parent cancelled.
		res.TimedOut = false
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, err
	}
	res.ExitCode = 0
	return res, nil
}
