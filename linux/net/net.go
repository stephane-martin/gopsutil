package net

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/sftp"
	"github.com/stephane-martin/gopsutil/internal/common"
	"golang.org/x/crypto/ssh"
)

type Net struct {
	sshClient  *ssh.Client
	sftpClient *sftp.Client
}

func NewNet(sshClient *ssh.Client, sftpClient *sftp.Client) *Net {
	return &Net{sshClient: sshClient, sftpClient: sftpClient}
}

func (n *Net) Interfaces() ([]InterfaceStat, error) {
	return Interfaces(n.sshClient)
}

func (n *Net) Connections(kind string) ([]ConnectionStat, error) {
	return Connections(n.sftpClient, kind)
}

func (n *Net) ConnectionsMax(kind string, max int) ([]ConnectionStat, error) {
	return ConnectionsMax(n.sftpClient, kind, max)
}

func (n *Net) ConnectionsPid(kind string, pid int) ([]ConnectionStat, error) {
	return ConnectionsPid(n.sftpClient, kind, pid)
}

type IOCountersStat struct {
	Name        string `json:"name"`        // interface name
	BytesSent   uint64 `json:"bytesSent"`   // number of bytes sent
	BytesRecv   uint64 `json:"bytesRecv"`   // number of bytes received
	PacketsSent uint64 `json:"packetsSent"` // number of packets sent
	PacketsRecv uint64 `json:"packetsRecv"` // number of packets received
	Errin       uint64 `json:"errin"`       // total number of errors while receiving
	Errout      uint64 `json:"errout"`      // total number of errors while sending
	Dropin      uint64 `json:"dropin"`      // total number of incoming packets which were dropped
	Dropout     uint64 `json:"dropout"`     // total number of outgoing packets which were dropped (always 0 on OSX and BSD)
	Fifoin      uint64 `json:"fifoin"`      // total number of FIFO buffers errors while receiving
	Fifoout     uint64 `json:"fifoout"`     // total number of FIFO buffers errors while sending

}

// Addr is implemented compatibility to psutil
type Addr struct {
	IP   string `json:"ip"`
	Port uint32 `json:"port"`
}

type ConnectionStat struct {
	Fd     uint32 `json:"fd"`
	Family uint32 `json:"family"`
	Type   uint32 `json:"type"`
	Laddr  Addr   `json:"localaddr"`
	Raddr  Addr   `json:"remoteaddr"`
	Status string `json:"status"`
	Uids   []int  `json:"uids"`
	Pid    int    `json:"pid"`
}

// System wide stats about different network protocols
type ProtoCountersStat struct {
	Protocol string           `json:"protocol"`
	Stats    map[string]int64 `json:"stats"`
}

// NetInterfaceAddr is designed for represent interface addresses
type InterfaceAddr struct {
	Addr string `json:"addr"`
}

type InterfaceStat struct {
	MTU          int             `json:"mtu"`          // maximum transmission unit
	Name         string          `json:"name"`         // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr string          `json:"hardwareaddr"` // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags        []string        `json:"flags"`        // e.g., FlagUp, FlagLoopback, FlagMulticast
	Addrs        []InterfaceAddr `json:"addrs"`
}

type ipAddr struct {
	Family            string `json:"family"`
	Local             string `json:"local"`
	PrefixLen         int    `json:"prefixlen"`
	Broadcast         string `json:"broadcast"`
	Scope             string `json:"scope"`
	Dynamic           bool   `json:"dynamic"`
	NoPrefixRoute     bool   `json:"noprefixroute"`
	Label             string `json:"label"`
	ValidLifeTime     int    `json:"valid_life_time"`
	PreferredLifeTime int    `json:"preferred_life_time"`
}

type ipLink struct {
	Index     int      `json:"ifindex"`
	Name      string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	QDisc     string   `json:"qdisc"`
	OPerState string   `json:"operstate"`
	Mode      string   `json:"linkmode"`
	Group     string   `json:"group"`
	TXQLen    int      `json:"txqlen"`
	Type      string   `json:"link_type"`
	Address   string   `json:"address"`
	Broadcast string   `json:"broadcast"`
	AddrInfo  []ipAddr `json:"addr_info"`
}

type FilterStat struct {
	ConnTrackCount int64 `json:"conntrackCount"`
	ConnTrackMax   int64 `json:"conntrackMax"`
}

var constMap = map[string]int{
	"unix": syscall.AF_UNIX,
	"TCP":  syscall.SOCK_STREAM,
	"UDP":  syscall.SOCK_DGRAM,
	"IPv4": syscall.AF_INET,
	"IPv6": syscall.AF_INET6,
}

func (n IOCountersStat) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

func (n ConnectionStat) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

func (n ProtoCountersStat) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

func (a Addr) String() string {
	s, _ := json.Marshal(a)
	return string(s)
}

func (n InterfaceStat) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

func (n InterfaceAddr) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

func Interfaces(sshClient *ssh.Client) ([]InterfaceStat, error) {
	return InterfacesWithContext(context.Background(), sshClient)
}

func InterfacesWithContext(ctx context.Context, sshClient *ssh.Client) ([]InterfaceStat, error) {
	invoke := common.RemoteInvoke{Client: sshClient}
	b, err := invoke.CommandWithContext(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, err
	}
	var links []ipLink
	err = json.Unmarshal(b, &links)
	if err != nil {
		return nil, err
	}
	ret := make([]InterfaceStat, 0, len(links))
	for _, ifi := range links {
		r := InterfaceStat{
			Name:         ifi.Name,
			MTU:          ifi.MTU,
			HardwareAddr: ifi.Address,
			Flags:        ifi.Flags,
		}
		r.Addrs = make([]InterfaceAddr, 0, len(ifi.AddrInfo))
		for _, addr := range ifi.AddrInfo {
			r.Addrs = append(r.Addrs, InterfaceAddr{
				Addr: addr.Local,
			})
		}
		ret = append(ret, r)
	}
	return ret, nil
}

func getIOCountersAll(n []IOCountersStat) ([]IOCountersStat, error) {
	r := IOCountersStat{
		Name: "all",
	}
	for _, nic := range n {
		r.BytesRecv += nic.BytesRecv
		r.PacketsRecv += nic.PacketsRecv
		r.Errin += nic.Errin
		r.Dropin += nic.Dropin
		r.BytesSent += nic.BytesSent
		r.PacketsSent += nic.PacketsSent
		r.Errout += nic.Errout
		r.Dropout += nic.Dropout
	}

	return []IOCountersStat{r}, nil
}

func parseNetLine(line string) (ConnectionStat, error) {
	f := strings.Fields(line)
	if len(f) < 8 {
		return ConnectionStat{}, fmt.Errorf("wrong line,%s", line)
	}

	if len(f) == 8 {
		f = append(f, f[7])
		f[7] = "unix"
	}

	pid, err := strconv.Atoi(f[1])
	if err != nil {
		return ConnectionStat{}, err
	}
	fd, err := strconv.Atoi(strings.Trim(f[3], "u"))
	if err != nil {
		return ConnectionStat{}, fmt.Errorf("unknown fd, %s", f[3])
	}
	netFamily, ok := constMap[f[4]]
	if !ok {
		return ConnectionStat{}, fmt.Errorf("unknown family, %s", f[4])
	}
	netType, ok := constMap[f[7]]
	if !ok {
		return ConnectionStat{}, fmt.Errorf("unknown type, %s", f[7])
	}

	var laddr, raddr Addr
	if f[7] == "unix" {
		laddr.IP = f[8]
	} else {
		laddr, raddr, err = parseNetAddr(f[8])
		if err != nil {
			return ConnectionStat{}, fmt.Errorf("failed to parse netaddr, %s", f[8])
		}
	}

	n := ConnectionStat{
		Fd:     uint32(fd),
		Family: uint32(netFamily),
		Type:   uint32(netType),
		Laddr:  laddr,
		Raddr:  raddr,
		Pid:    pid,
	}
	if len(f) == 10 {
		n.Status = strings.Trim(f[9], "()")
	}

	return n, nil
}

func parseNetAddr(line string) (laddr Addr, raddr Addr, err error) {
	parse := func(l string) (Addr, error) {
		host, port, err := net.SplitHostPort(l)
		if err != nil {
			return Addr{}, fmt.Errorf("wrong addr, %s", l)
		}
		lport, err := strconv.Atoi(port)
		if err != nil {
			return Addr{}, err
		}
		return Addr{IP: host, Port: uint32(lport)}, nil
	}

	addrs := strings.Split(line, "->")
	if len(addrs) == 0 {
		return laddr, raddr, fmt.Errorf("wrong netaddr, %s", line)
	}
	laddr, err = parse(addrs[0])
	if len(addrs) == 2 { // remote addr exists
		raddr, err = parse(addrs[1])
		if err != nil {
			return laddr, raddr, err
		}
	}

	return laddr, raddr, err
}
