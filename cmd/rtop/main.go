package main

import (
	"fmt"
	"os"

	"github.com/stephane-martin/gopsutil"
	"golang.org/x/crypto/ssh"
)

func main() {
	fmt.Println("vim-go")
	pass := ssh.Password("***")
	config := &ssh.ClientConfig{
		User:            "stef",
		Auth:            []ssh.AuthMethod{pass},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "127.0.0.1:22", config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer client.Close()
	u, err := gopsutil.New(client)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer u.Close()
	procs, err := u.Processes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	for _, proc := range procs {
		name, _ := proc.Name()
		cmd, _ := proc.Cmdline()
		fmt.Println(proc.Pid, name, cmd)
	}
	fmt.Println()
	infos, err := u.HostInfo()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	fmt.Println(infos)
}
