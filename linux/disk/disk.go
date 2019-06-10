package disk

import (
	"encoding/json"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Disk struct {
	sftpClient *sftp.Client
	sshClient  *ssh.Client
}

func NewDisk(sshClient *ssh.Client, sftpClient *sftp.Client) *Disk {
	return &Disk{sshClient: sshClient, sftpClient: sftpClient}
}

func (d *Disk) Label(name string) (string, error) {
	return GetLabel(d.sftpClient, name)
}

func (d *Disk) IOCounters(names ...string) (map[string]IOCountersStat, error) {
	return IOCounters(d.sftpClient, names...)
}

func (d *Disk) Partitions(all bool) ([]PartitionStat, error) {
	return Partitions(d.sftpClient, all)
}

func (d *Disk) Usage(path string) (*UsageStat, error) {
	return Usage(d.sftpClient, path)
}

type UsageStat struct {
	Path              string  `json:"path"`
	Total             uint64  `json:"total"`
	Free              uint64  `json:"free"`
	Used              uint64  `json:"used"`
	UsedPercent       float64 `json:"usedPercent"`
	InodesTotal       uint64  `json:"inodesTotal"`
	InodesUsed        uint64  `json:"inodesUsed"`
	InodesFree        uint64  `json:"inodesFree"`
	InodesUsedPercent float64 `json:"inodesUsedPercent"`
}

type PartitionStat struct {
	Device     string `json:"device"`
	Mountpoint string `json:"mountpoint"`
	Fstype     string `json:"fstype"`
	Opts       string `json:"opts"`
}

type IOCountersStat struct {
	ReadCount        uint64 `json:"readCount"`
	MergedReadCount  uint64 `json:"mergedReadCount"`
	WriteCount       uint64 `json:"writeCount"`
	MergedWriteCount uint64 `json:"mergedWriteCount"`
	ReadBytes        uint64 `json:"readBytes"`
	WriteBytes       uint64 `json:"writeBytes"`
	ReadTime         uint64 `json:"readTime"`
	WriteTime        uint64 `json:"writeTime"`
	IopsInProgress   uint64 `json:"iopsInProgress"`
	IoTime           uint64 `json:"ioTime"`
	WeightedIO       uint64 `json:"weightedIO"`
	Name             string `json:"name"`
	Label            string `json:"label"`
}

func (d UsageStat) String() string {
	s, _ := json.Marshal(d)
	return string(s)
}

func (d PartitionStat) String() string {
	s, _ := json.Marshal(d)
	return string(s)
}

func (d IOCountersStat) String() string {
	s, _ := json.Marshal(d)
	return string(s)
}
