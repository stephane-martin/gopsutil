package docker

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"github.com/stephane-martin/gopsutil/internal/common"
	"github.com/stephane-martin/gopsutil/linux/cpu"
	"golang.org/x/crypto/ssh"
)

type Docker struct {
	tick       float64
	sftpClient *sftp.Client
	sshClient  *ssh.Client
}

func NewDocker(sshClient *ssh.Client, sftpClient *sftp.Client) (*Docker, error) {
	out, err := common.SSHInvoke(sshClient).CommandWithContext(context.Background(), "getconf", "CLK_TCK")
	if err != nil {
		return nil, err
	}
	// ignore errors
	tick, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		tick = 100
	}
	return &Docker{tick: tick, sftpClient: sftpClient, sshClient: sshClient}, nil
}

// GetDockerStat returns a list of Docker basic stats.
// This requires certain permission.
func (d Docker) GetStat() ([]CgroupDockerStat, error) {
	return d.GetDockerStatWithContext(context.Background())
}

func (d Docker) GetDockerStatWithContext(ctx context.Context) ([]CgroupDockerStat, error) {
	invoke := common.RemoteInvoke{Client: d.sshClient}
	out, err := invoke.CommandWithContext(ctx, "docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}")
	if err != nil {
		return []CgroupDockerStat{}, err
	}
	lines := strings.Split(string(out), "\n")
	ret := make([]CgroupDockerStat, 0, len(lines))

	for _, l := range lines {
		if l == "" {
			continue
		}
		cols := strings.Split(l, "|")
		if len(cols) != 4 {
			continue
		}
		names := strings.Split(cols[2], ",")
		stat := CgroupDockerStat{
			ContainerID: cols[0],
			Name:        names[1],
			Image:       cols[1],
			Status:      cols[3],
			Running:     strings.Contains(cols[3], "Up"),
		}
		ret = append(ret, stat)
	}

	return ret, nil
}

// GetDockerIDList returnes a list of DockerID.
// This requires certain permission.
func (d Docker) GetDockerIDList() ([]string, error) {
	return d.GetDockerIDListWithContext(context.Background())
}

func (d Docker) GetDockerIDListWithContext(ctx context.Context) ([]string, error) {
	invoke := common.RemoteInvoke{Client: d.sshClient}
	out, err := invoke.CommandWithContext(ctx, "docker", "ps", "-q", "--no-trunc")
	if err != nil {
		return []string{}, err
	}
	lines := strings.Split(string(out), "\n")
	ret := make([]string, 0, len(lines))

	for _, l := range lines {
		if l == "" {
			continue
		}
		ret = append(ret, l)
	}

	return ret, nil
}

// CgroupCPU returns specified cgroup id CPU status.
// containerID is same as docker id if you use docker.
// If you use container via systemd.slice, you could use
// containerID = docker-<container id>.scope and base=/sys/fs/cgroup/cpuacct/system.slice/
func (d Docker) CgroupCPU(containerID string, base string) (*cpu.TimesStat, error) {
	return d.CgroupCPUWithContext(context.Background(), containerID, base)
}

// CgroupCPUUsage returnes specified cgroup id CPU usage.
// containerID is same as docker id if you use docker.
// If you use container via systemd.slice, you could use
// containerID = docker-<container id>.scope and base=/sys/fs/cgroup/cpuacct/system.slice/
func (d Docker) CgroupCPUUsage(containerID string, base string) (float64, error) {
	return d.CgroupCPUUsageWithContext(context.Background(), containerID, base)
}

func (d Docker) CgroupCPUWithContext(ctx context.Context, containerID string, base string) (*cpu.TimesStat, error) {
	statfile := getCgroupFilePath(d.sftpClient, containerID, base, "cpuacct", "cpuacct.stat")
	lines, err := common.RemoteReadLines(d.sftpClient, statfile)
	if err != nil {
		return nil, err
	}
	// empty containerID means all cgroup
	if len(containerID) == 0 {
		containerID = "all"
	}
	ret := &cpu.TimesStat{CPU: containerID}
	for _, line := range lines {
		fields := strings.Split(line, " ")
		if fields[0] == "user" {
			user, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				ret.User = user / d.tick
			}
		}
		if fields[0] == "system" {
			system, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				ret.System = system / d.tick
			}
		}
	}
	return ret, nil
}

func (d Docker) CgroupCPUUsageWithContext(ctx context.Context, containerID, base string) (float64, error) {
	usagefile := getCgroupFilePath(d.sftpClient, containerID, base, "cpuacct", "cpuacct.usage")
	lines, err := common.RemoteReadLinesOffsetN(d.sftpClient, usagefile, 0, 1)
	if err != nil {
		return 0.0, err
	}

	ns, err := strconv.ParseFloat(lines[0], 64)
	if err != nil {
		return 0.0, err
	}

	return ns / nanoseconds, nil
}

func (d Docker) CgroupCPUDocker(containerid string) (*cpu.TimesStat, error) {
	return d.CgroupCPUDockerWithContext(context.Background(), containerid)
}

func (d Docker) CgroupCPUUsageDocker(containerid string) (float64, error) {
	return d.CgroupCPUDockerUsageWithContext(context.Background(), containerid)
}

func (d Docker) CgroupCPUDockerWithContext(ctx context.Context, containerid string) (*cpu.TimesStat, error) {
	return d.CgroupCPU(containerid, common.HostSys("fs/cgroup/cpuacct/docker"))
}

func (d Docker) CgroupCPUDockerUsageWithContext(ctx context.Context, containerid string) (float64, error) {
	return d.CgroupCPUUsage(containerid, common.HostSys("fs/cgroup/cpuacct/docker"))
}

func (d Docker) CgroupMem(containerID string, base string) (*CgroupMemStat, error) {
	return d.CgroupMemWithContext(context.Background(), containerID, base)
}

func (d Docker) CgroupMemWithContext(ctx context.Context, containerID string, base string) (*CgroupMemStat, error) {
	statfile := getCgroupFilePath(d.sftpClient, containerID, base, "memory", "memory.stat")

	// empty containerID means all cgroup
	if len(containerID) == 0 {
		containerID = "all"
	}
	lines, err := common.RemoteReadLines(d.sftpClient, statfile)
	if err != nil {
		return nil, err
	}
	ret := &CgroupMemStat{ContainerID: containerID}
	for _, line := range lines {
		fields := strings.Split(line, " ")
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "cache":
			ret.Cache = v
		case "rss":
			ret.RSS = v
		case "rssHuge":
			ret.RSSHuge = v
		case "mappedFile":
			ret.MappedFile = v
		case "pgpgin":
			ret.Pgpgin = v
		case "pgpgout":
			ret.Pgpgout = v
		case "pgfault":
			ret.Pgfault = v
		case "pgmajfault":
			ret.Pgmajfault = v
		case "inactiveAnon", "inactive_anon":
			ret.InactiveAnon = v
		case "activeAnon", "active_anon":
			ret.ActiveAnon = v
		case "inactiveFile", "inactive_file":
			ret.InactiveFile = v
		case "activeFile", "active_file":
			ret.ActiveFile = v
		case "unevictable":
			ret.Unevictable = v
		case "hierarchicalMemoryLimit", "hierarchical_memory_limit":
			ret.HierarchicalMemoryLimit = v
		case "totalCache", "total_cache":
			ret.TotalCache = v
		case "totalRss", "total_rss":
			ret.TotalRSS = v
		case "totalRssHuge", "total_rss_huge":
			ret.TotalRSSHuge = v
		case "totalMappedFile", "total_mapped_file":
			ret.TotalMappedFile = v
		case "totalPgpgin", "total_pgpgin":
			ret.TotalPgpgIn = v
		case "totalPgpgout", "total_pgpgout":
			ret.TotalPgpgOut = v
		case "totalPgfault", "total_pgfault":
			ret.TotalPgFault = v
		case "totalPgmajfault", "total_pgmajfault":
			ret.TotalPgMajFault = v
		case "totalInactiveAnon", "total_inactive_anon":
			ret.TotalInactiveAnon = v
		case "totalActiveAnon", "total_active_anon":
			ret.TotalActiveAnon = v
		case "totalInactiveFile", "total_inactive_file":
			ret.TotalInactiveFile = v
		case "totalActiveFile", "total_active_file":
			ret.TotalActiveFile = v
		case "totalUnevictable", "total_unevictable":
			ret.TotalUnevictable = v
		}
	}

	r, err := getCgroupMemFile(d.sftpClient, containerID, base, "memory.usage_in_bytes")
	if err == nil {
		ret.MemUsageInBytes = r
	}
	r, err = getCgroupMemFile(d.sftpClient, containerID, base, "memory.max_usage_in_bytes")
	if err == nil {
		ret.MemMaxUsageInBytes = r
	}
	r, err = getCgroupMemFile(d.sftpClient, containerID, base, "memoryLimitInBbytes")
	if err == nil {
		ret.MemLimitInBytes = r
	}
	r, err = getCgroupMemFile(d.sftpClient, containerID, base, "memoryFailcnt")
	if err == nil {
		ret.MemFailCnt = r
	}

	return ret, nil
}

func (d Docker) CgroupMemDocker(containerID string) (*CgroupMemStat, error) {
	return d.CgroupMemDockerWithContext(context.Background(), containerID)
}

func (d Docker) CgroupMemDockerWithContext(ctx context.Context, containerID string) (*CgroupMemStat, error) {
	return d.CgroupMem(containerID, common.HostSys("fs/cgroup/memory/docker"))
}

// getCgroupFilePath constructs file path to get targeted stats file.
func getCgroupFilePath(sftpClient *sftp.Client, containerID, base, target, file string) string {
	if len(base) == 0 {
		base = common.HostSys(fmt.Sprintf("fs/cgroup/%s/docker", target))
	}
	statfile := path.Join(base, containerID, file)

	if _, err := sftpClient.Stat(statfile); os.IsNotExist(err) {
		statfile = path.Join(common.HostSys(fmt.Sprintf("fs/cgroup/%s/system.slice", target)), "docker-"+containerID+".scope", file)
	}

	return statfile
}

// getCgroupMemFile reads a cgroup file and return the contents as uint64.
func getCgroupMemFile(sftpClient *sftp.Client, containerID, base, file string) (uint64, error) {
	statfile := getCgroupFilePath(sftpClient, containerID, base, "memory", file)
	lines, err := common.RemoteReadLines(sftpClient, statfile)
	if err != nil {
		return 0, err
	}
	if len(lines) != 1 {
		return 0, fmt.Errorf("wrong format file: %s", statfile)
	}
	return strconv.ParseUint(lines[0], 10, 64)
}
