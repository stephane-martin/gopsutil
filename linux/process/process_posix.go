// +build linux freebsd openbsd darwin

package process

import (
	"context"
	"os/user"
	"strconv"
	"syscall"

	"github.com/stephane-martin/gopsutil/internal/common"
	"golang.org/x/sys/unix"
)

// SendSignal sends a unix.Signal to the process.
func (p *Process) SendSignal(sig syscall.Signal) error {
	return p.SendSignalWithContext(context.Background(), sig)
}

func (p *Process) SendSignalWithContext(ctx context.Context, sig syscall.Signal) error {
	invoke := common.RemoteInvoke{Client: p.sshClient}
	_, err := invoke.CommandWithContext(ctx, "kill", "--signal", strconv.Itoa(int(sig)), strconv.Itoa(p.Pid))
	return err
}

// Suspend sends SIGSTOP to the process.
func (p *Process) Suspend() error {
	return p.SuspendWithContext(context.Background())
}

func (p *Process) SuspendWithContext(ctx context.Context) error {
	return p.SendSignal(unix.SIGSTOP)
}

// Resume sends SIGCONT to the process.
func (p *Process) Resume() error {
	return p.ResumeWithContext(context.Background())
}

func (p *Process) ResumeWithContext(ctx context.Context) error {
	return p.SendSignal(unix.SIGCONT)
}

// Terminate sends SIGTERM to the process.
func (p *Process) Terminate() error {
	return p.TerminateWithContext(context.Background())
}

func (p *Process) TerminateWithContext(ctx context.Context) error {
	return p.SendSignal(unix.SIGTERM)
}

// Kill sends SIGKILL to the process.
func (p *Process) Kill() error {
	return p.KillWithContext(context.Background())
}

func (p *Process) KillWithContext(ctx context.Context) error {
	return p.SendSignal(unix.SIGKILL)
}

// Username returns a username of the process.
func (p *Process) Username() (string, error) {
	return p.UsernameWithContext(context.Background())
}

func (p *Process) UsernameWithContext(ctx context.Context) (string, error) {
	uids, err := p.Uids()
	if err != nil {
		return "", err
	}
	if len(uids) > 0 {
		u, err := user.LookupId(strconv.Itoa(int(uids[0])))
		if err != nil {
			return "", err
		}
		return u.Username, nil
	}
	return "", nil
}
