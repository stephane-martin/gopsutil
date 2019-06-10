// +build linux

package disk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"github.com/stephane-martin/gopsutil/internal/common"
)

const (
	SectorSize = 512
)
const (
	// man statfs
	ADFS_SUPER_MAGIC            = 0xadf5
	AFFS_SUPER_MAGIC            = 0xADFF
	BDEVFS_MAGIC                = 0x62646576
	BEFS_SUPER_MAGIC            = 0x42465331
	BFS_MAGIC                   = 0x1BADFACE
	BINFMTFS_MAGIC              = 0x42494e4d
	BTRFS_SUPER_MAGIC           = 0x9123683E
	CGROUP_SUPER_MAGIC          = 0x27e0eb
	CIFS_MAGIC_NUMBER           = 0xFF534D42
	CODA_SUPER_MAGIC            = 0x73757245
	COH_SUPER_MAGIC             = 0x012FF7B7
	CRAMFS_MAGIC                = 0x28cd3d45
	DEBUGFS_MAGIC               = 0x64626720
	DEVFS_SUPER_MAGIC           = 0x1373
	DEVPTS_SUPER_MAGIC          = 0x1cd1
	EFIVARFS_MAGIC              = 0xde5e81e4
	EFS_SUPER_MAGIC             = 0x00414A53
	EXT_SUPER_MAGIC             = 0x137D
	EXT2_OLD_SUPER_MAGIC        = 0xEF51
	EXT2_SUPER_MAGIC            = 0xEF53
	EXT3_SUPER_MAGIC            = 0xEF53
	EXT4_SUPER_MAGIC            = 0xEF53
	FUSE_SUPER_MAGIC            = 0x65735546
	FUTEXFS_SUPER_MAGIC         = 0xBAD1DEA
	HFS_SUPER_MAGIC             = 0x4244
	HOSTFS_SUPER_MAGIC          = 0x00c0ffee
	HPFS_SUPER_MAGIC            = 0xF995E849
	HUGETLBFS_MAGIC             = 0x958458f6
	ISOFS_SUPER_MAGIC           = 0x9660
	JFFS2_SUPER_MAGIC           = 0x72b6
	JFS_SUPER_MAGIC             = 0x3153464a
	MINIX_SUPER_MAGIC           = 0x137F /* orig. minix */
	MINIX_SUPER_MAGIC2          = 0x138F /* 30 char minix */
	MINIX2_SUPER_MAGIC          = 0x2468 /* minix V2 */
	MINIX2_SUPER_MAGIC2         = 0x2478 /* minix V2, 30 char names */
	MINIX3_SUPER_MAGIC          = 0x4d5a /* minix V3 fs, 60 char names */
	MQUEUE_MAGIC                = 0x19800202
	MSDOS_SUPER_MAGIC           = 0x4d44
	NCP_SUPER_MAGIC             = 0x564c
	NFS_SUPER_MAGIC             = 0x6969
	NILFS_SUPER_MAGIC           = 0x3434
	NTFS_SB_MAGIC               = 0x5346544e
	OCFS2_SUPER_MAGIC           = 0x7461636f
	OPENPROM_SUPER_MAGIC        = 0x9fa1
	PIPEFS_MAGIC                = 0x50495045
	PROC_SUPER_MAGIC            = 0x9fa0
	PSTOREFS_MAGIC              = 0x6165676C
	QNX4_SUPER_MAGIC            = 0x002f
	QNX6_SUPER_MAGIC            = 0x68191122
	RAMFS_MAGIC                 = 0x858458f6
	REISERFS_SUPER_MAGIC        = 0x52654973
	ROMFS_MAGIC                 = 0x7275
	SELINUX_MAGIC               = 0xf97cff8c
	SMACK_MAGIC                 = 0x43415d53
	SMB_SUPER_MAGIC             = 0x517B
	SOCKFS_MAGIC                = 0x534F434B
	SQUASHFS_MAGIC              = 0x73717368
	SYSFS_MAGIC                 = 0x62656572
	SYSV2_SUPER_MAGIC           = 0x012FF7B6
	SYSV4_SUPER_MAGIC           = 0x012FF7B5
	TMPFS_MAGIC                 = 0x01021994
	UDF_SUPER_MAGIC             = 0x15013346
	UFS_MAGIC                   = 0x00011954
	USBDEVICE_SUPER_MAGIC       = 0x9fa2
	V9FS_MAGIC                  = 0x01021997
	VXFS_SUPER_MAGIC            = 0xa501FCF5
	XENFS_SUPER_MAGIC           = 0xabba1974
	XENIX_SUPER_MAGIC           = 0x012FF7B4
	XFS_SUPER_MAGIC             = 0x58465342
	_XIAFS_SUPER_MAGIC          = 0x012FD16D
	AFS_SUPER_MAGIC             = 0x5346414F
	AUFS_SUPER_MAGIC            = 0x61756673
	ANON_INODE_FS_SUPER_MAGIC   = 0x09041934
	CEPH_SUPER_MAGIC            = 0x00C36400
	ECRYPTFS_SUPER_MAGIC        = 0xF15F
	FAT_SUPER_MAGIC             = 0x4006
	FHGFS_SUPER_MAGIC           = 0x19830326
	FUSEBLK_SUPER_MAGIC         = 0x65735546
	FUSECTL_SUPER_MAGIC         = 0x65735543
	GFS_SUPER_MAGIC             = 0x1161970
	GPFS_SUPER_MAGIC            = 0x47504653
	MTD_INODE_FS_SUPER_MAGIC    = 0x11307854
	INOTIFYFS_SUPER_MAGIC       = 0x2BAD1DEA
	ISOFS_R_WIN_SUPER_MAGIC     = 0x4004
	ISOFS_WIN_SUPER_MAGIC       = 0x4000
	JFFS_SUPER_MAGIC            = 0x07C0
	KAFS_SUPER_MAGIC            = 0x6B414653
	LUSTRE_SUPER_MAGIC          = 0x0BD00BD0
	NFSD_SUPER_MAGIC            = 0x6E667364
	PANFS_SUPER_MAGIC           = 0xAAD7AAEA
	RPC_PIPEFS_SUPER_MAGIC      = 0x67596969
	SECURITYFS_SUPER_MAGIC      = 0x73636673
	UFS_BYTESWAPPED_SUPER_MAGIC = 0x54190100
	VMHGFS_SUPER_MAGIC          = 0xBACBACBC
	VZFS_SUPER_MAGIC            = 0x565A4653
	ZFS_SUPER_MAGIC             = 0x2FC12FC1
)

// Partitions returns disk partitions. If all is false, returns
// physical devices only (e.g. hard disks, cd-rom drives, USB keys)
// and ignore all others (e.g. memory partitions such as /dev/shm)
func Partitions(client *sftp.Client, all bool) ([]PartitionStat, error) {
	return PartitionsWithContext(context.Background(), client, all)
}

func PartitionsWithContext(ctx context.Context, client *sftp.Client, all bool) ([]PartitionStat, error) {
	useMounts := false

	filename := common.HostProc("self/mountinfo")
	lines, err := common.RemoteReadLines(client, filename)
	if err != nil {
		if err != err.(*os.PathError) {
			return nil, err
		}
		// if kernel does not support self/mountinfo, fallback to self/mounts (<2.6.26)
		useMounts = true
		filename = common.HostProc("self/mounts")
		lines, err = common.RemoteReadLines(client, filename)
		if err != nil {
			return nil, err
		}
	}

	fs, err := getFileSystems(client)
	if err != nil {
		return nil, err
	}

	ret := make([]PartitionStat, 0, len(lines))

	for _, line := range lines {
		var d PartitionStat
		if useMounts {
			fields := strings.Fields(line)

			d = PartitionStat{
				Device:     fields[0],
				Mountpoint: unescapeFstab(fields[1]),
				Fstype:     fields[2],
				Opts:       fields[3],
			}

			if !all {
				if d.Device == "none" || !common.StringsHas(fs, d.Fstype) {
					continue
				}
			}
		} else {
			// a line of self/mountinfo has the following structure:
			// 36  35  98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
			// (1) (2) (3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

			// split the mountinfo line by the separator hyphen
			parts := strings.Split(line, " - ")
			if len(parts) != 2 {
				return nil, fmt.Errorf("found invalid mountinfo line in file %s: %s ", filename, line)
			}

			fields := strings.Fields(parts[0])
			blockDeviceID := fields[2]
			mountPoint := fields[4]
			mountOpts := fields[5]

			fields = strings.Fields(parts[1])
			fstype := fields[0]
			device := fields[1]

			d = PartitionStat{
				Device:     device,
				Mountpoint: mountPoint,
				Fstype:     fstype,
				Opts:       mountOpts,
			}

			if !all {
				if d.Device == "none" || !common.StringsHas(fs, d.Fstype) {
					continue
				}
			}

			// /dev/root is not the real device name
			// so we get the real device name from its major/minor number
			if d.Device == "/dev/root" {
				devpath, err := client.ReadLink(common.HostSys("/dev/block/" + blockDeviceID))
				if err != nil {
					return nil, err
				}
				d.Device = strings.Replace(d.Device, "root", filepath.Base(devpath), 1)
			}
		}
		ret = append(ret, d)
	}

	return ret, nil
}

// getFileSystems returns supported filesystems from /proc/filesystems
func getFileSystems(client *sftp.Client) ([]string, error) {
	filename := common.HostProc("filesystems")
	lines, err := common.RemoteReadLines(client, filename)
	if err != nil {
		return nil, err
	}
	var ret []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "nodev") {
			ret = append(ret, strings.TrimSpace(line))
			continue
		}
		t := strings.Split(line, "\t")
		if len(t) != 2 || t[1] != "zfs" {
			continue
		}
		ret = append(ret, strings.TrimSpace(t[1]))
	}

	return ret, nil
}

func IOCounters(client *sftp.Client, names ...string) (map[string]IOCountersStat, error) {
	return IOCountersWithContext(context.Background(), client, names...)
}

func IOCountersWithContext(ctx context.Context, client *sftp.Client, names ...string) (map[string]IOCountersStat, error) {
	filename := common.HostProc("diskstats")
	lines, err := common.RemoteReadLines(client, filename)
	if err != nil {
		return nil, err
	}
	ret := make(map[string]IOCountersStat)
	var empty IOCountersStat

	// use only basename such as "/dev/sda1" to "sda1"
	for i, name := range names {
		names[i] = filepath.Base(name)
	}

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			// malformed line in /proc/diskstats, avoid panic by ignoring.
			continue
		}
		name := fields[2]

		if len(names) > 0 && !common.StringsHas(names, name) {
			continue
		}

		reads, err := strconv.ParseUint((fields[3]), 10, 64)
		if err != nil {
			return ret, err
		}
		mergedReads, err := strconv.ParseUint((fields[4]), 10, 64)
		if err != nil {
			return ret, err
		}
		rbytes, err := strconv.ParseUint((fields[5]), 10, 64)
		if err != nil {
			return ret, err
		}
		rtime, err := strconv.ParseUint((fields[6]), 10, 64)
		if err != nil {
			return ret, err
		}
		writes, err := strconv.ParseUint((fields[7]), 10, 64)
		if err != nil {
			return ret, err
		}
		mergedWrites, err := strconv.ParseUint((fields[8]), 10, 64)
		if err != nil {
			return ret, err
		}
		wbytes, err := strconv.ParseUint((fields[9]), 10, 64)
		if err != nil {
			return ret, err
		}
		wtime, err := strconv.ParseUint((fields[10]), 10, 64)
		if err != nil {
			return ret, err
		}
		iopsInProgress, err := strconv.ParseUint((fields[11]), 10, 64)
		if err != nil {
			return ret, err
		}
		iotime, err := strconv.ParseUint((fields[12]), 10, 64)
		if err != nil {
			return ret, err
		}
		weightedIO, err := strconv.ParseUint((fields[13]), 10, 64)
		if err != nil {
			return ret, err
		}
		d := IOCountersStat{
			ReadBytes:        rbytes * SectorSize,
			WriteBytes:       wbytes * SectorSize,
			ReadCount:        reads,
			WriteCount:       writes,
			MergedReadCount:  mergedReads,
			MergedWriteCount: mergedWrites,
			ReadTime:         rtime,
			WriteTime:        wtime,
			IopsInProgress:   iopsInProgress,
			IoTime:           iotime,
			WeightedIO:       weightedIO,
		}
		if d == empty {
			continue
		}
		d.Name = name
		label, err := GetLabel(client, name)
		if err == nil {
			d.Label = label
		}
		ret[name] = d
	}
	return ret, nil
}

// GetLabel returns label of given device or empty string on error.
// Name of device is expected, eg. /dev/sda
// Supports label based on devicemapper name
// See https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-block-dm
func GetLabel(client *sftp.Client, name string) (string, error) {
	// Try label based on devicemapper name
	dmname_filename := common.HostSys(fmt.Sprintf("block/%s/dm/name", name))
	exists, err := common.RemotePathExists(client, dmname_filename)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	dmname, err := common.RemoteReadFile(client, dmname_filename)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(dmname)), nil
}
