// +build linux

package mem

import (
	"bytes"
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"github.com/stephane-martin/gopsutil/internal/common"
	"golang.org/x/crypto/ssh"
)

type VirtualMemoryExStat struct {
	ActiveFile   uint64 `json:"activefile"`
	InactiveFile uint64 `json:"inactivefile"`
}

func VirtualMemory(client *sftp.Client, pagesize uint64) (*VirtualMemoryStat, error) {
	return VirtualMemoryWithContext(context.Background(), client, pagesize)
}

func VirtualMemoryWithContext(ctx context.Context, client *sftp.Client, pagesize uint64) (*VirtualMemoryStat, error) {
	filename := common.HostProc("meminfo")
	lines, _ := common.RemoteReadLines(client, filename)

	// flag if MemAvailable is in /proc/meminfo (kernel 3.14+)
	memavail := false
	activeFile := false   // "Active(file)" not available: 2.6.28 / Dec 2008
	inactiveFile := false // "Inactive(file)" not available: 2.6.28 / Dec 2008
	sReclaimable := false // "SReclaimable:" not available: 2.6.19 / Nov 2006

	ret := &VirtualMemoryStat{}
	retEx := &VirtualMemoryExStat{}

	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) != 2 {
			continue
		}
		key := strings.TrimSpace(fields[0])
		value := strings.TrimSpace(fields[1])
		value = strings.Replace(value, " kB", "", -1)

		t, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return ret, err
		}
		switch key {
		case "MemTotal":
			ret.Total = t * 1024
		case "MemFree":
			ret.Free = t * 1024
		case "MemAvailable":
			memavail = true
			ret.Available = t * 1024
		case "Buffers":
			ret.Buffers = t * 1024
		case "Cached":
			ret.Cached = t * 1024
		case "Active":
			ret.Active = t * 1024
		case "Inactive":
			ret.Inactive = t * 1024
		case "Active(file)":
			activeFile = true
			retEx.ActiveFile = t * 1024
		case "InActive(file)":
			inactiveFile = true
			retEx.InactiveFile = t * 1024
		case "Writeback":
			ret.Writeback = t * 1024
		case "WritebackTmp":
			ret.WritebackTmp = t * 1024
		case "Dirty":
			ret.Dirty = t * 1024
		case "Shmem":
			ret.Shared = t * 1024
		case "Slab":
			ret.Slab = t * 1024
		case "SReclaimable":
			sReclaimable = true
			ret.SReclaimable = t * 1024
		case "PageTables":
			ret.PageTables = t * 1024
		case "SwapCached":
			ret.SwapCached = t * 1024
		case "CommitLimit":
			ret.CommitLimit = t * 1024
		case "Committed_AS":
			ret.CommittedAS = t * 1024
		case "HighTotal":
			ret.HighTotal = t * 1024
		case "HighFree":
			ret.HighFree = t * 1024
		case "LowTotal":
			ret.LowTotal = t * 1024
		case "LowFree":
			ret.LowFree = t * 1024
		case "SwapTotal":
			ret.SwapTotal = t * 1024
		case "SwapFree":
			ret.SwapFree = t * 1024
		case "Mapped":
			ret.Mapped = t * 1024
		case "VmallocTotal":
			ret.VMallocTotal = t * 1024
		case "VmallocUsed":
			ret.VMallocUsed = t * 1024
		case "VmallocChunk":
			ret.VMallocChunk = t * 1024
		case "HugePages_Total":
			ret.HugePagesTotal = t
		case "HugePages_Free":
			ret.HugePagesFree = t
		case "Hugepagesize":
			ret.HugePageSize = t * 1024
		}
	}

	ret.Cached += ret.SReclaimable

	if !memavail {
		if activeFile && inactiveFile && sReclaimable {
			ret.Available = calcuateAvailVmem(client, ret, retEx, pagesize)
		} else {
			ret.Available = ret.Cached + ret.Free
		}
	}

	ret.Used = ret.Total - ret.Free - ret.Buffers - ret.Cached
	ret.UsedPercent = float64(ret.Used) / float64(ret.Total) * 100.0

	return ret, nil
}

func PageSize(client *ssh.Client) (uint64, error) {
	exe := common.RemoteInvoke{Client: client}
	b, err := exe.Command("getconf", "PAGESIZE")
	if err != nil {
		return 0, err
	}
	size, err := strconv.ParseUint(string(bytes.TrimSpace(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// calcuateAvailVmem is a fallback under kernel 3.14 where /proc/meminfo does not provide
// "MemAvailable:" column. It reimplements an algorithm from the link below
// https://github.com/giampaolo/psutil/pull/890
func calcuateAvailVmem(sftpClient *sftp.Client, ret *VirtualMemoryStat, retEx *VirtualMemoryExStat, pagesize uint64) uint64 {
	var watermarkLow uint64

	fn := common.HostProc("zoneinfo")
	lines, err := common.RemoteReadLines(sftpClient, fn)

	if err != nil {
		return ret.Free + ret.Cached // fallback under kernel 2.6.13
	}

	watermarkLow = 0

	for _, line := range lines {
		fields := strings.Fields(line)

		if strings.HasPrefix(fields[0], "low") {
			lowValue, err := strconv.ParseUint(fields[1], 10, 64)

			if err != nil {
				lowValue = 0
			}
			watermarkLow += lowValue
		}
	}

	watermarkLow *= pagesize

	availMemory := ret.Free - watermarkLow
	pageCache := retEx.ActiveFile + retEx.InactiveFile
	pageCache -= uint64(math.Min(float64(pageCache/2), float64(watermarkLow)))
	availMemory += pageCache
	availMemory += ret.SReclaimable - uint64(math.Min(float64(ret.SReclaimable/2.0), float64(watermarkLow)))

	if availMemory < 0 {
		availMemory = 0
	}

	return availMemory
}
