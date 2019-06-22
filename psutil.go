package gopsutil

import (
	"bytes"
	"errors"
	"strings"

	"github.com/pkg/sftp"
	"github.com/stephane-martin/gopsutil/linux/battery"
	"github.com/stephane-martin/gopsutil/linux/cpu"
	"github.com/stephane-martin/gopsutil/linux/disk"
	"github.com/stephane-martin/gopsutil/linux/docker"
	"github.com/stephane-martin/gopsutil/linux/host"
	"github.com/stephane-martin/gopsutil/linux/load"
	"github.com/stephane-martin/gopsutil/linux/mem"
	"github.com/stephane-martin/gopsutil/linux/net"
	"github.com/stephane-martin/gopsutil/linux/process"
	"golang.org/x/crypto/ssh"
)

type PSUtil struct {
	sshClient  *ssh.Client
	sftpClient *sftp.Client
}

func New(client *ssh.Client) (*PSUtil, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	b, err := sess.Output("uname -s")
	if err != nil {
		return nil, err
	}
	output := strings.ToLower(string(bytes.TrimSpace(b)))
	if output != "linux" {
		return nil, errors.New("only remote linux is supported")
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	return &PSUtil{sshClient: client, sftpClient: sftpClient}, nil
}

func (u *PSUtil) Close() error {
	return u.sftpClient.Close()
}

func (u *PSUtil) AvgLoad() (*load.AvgStat, error) {
	return load.Avg(u.sftpClient)
}

func (u *PSUtil) Misc() (*load.MiscStat, error) {
	return load.Misc(u.sftpClient)
}

func (u *PSUtil) CPU() (*cpu.CPU, error) {
	return cpu.NewCPU(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Disk() *disk.Disk {
	return disk.NewDisk(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Mem() (*mem.Mem, error) {
	return mem.NewMem(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Net() *net.Net {
	return net.NewNet(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Processes() ([]*process.Process, error) {
	return process.Processes(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Pids() ([]int, error) {
	return process.Pids(u.sftpClient)
}

func (u *PSUtil) Host() *host.Host {
	return host.NewHost(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Docker() (*docker.Docker, error) {
	return docker.NewDocker(u.sshClient, u.sftpClient)
}

func (u *PSUtil) Battery() ([]*battery.Battery, error) {
	return battery.GetAll(u.sftpClient)
}
