package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"github.com/stephane-martin/gopsutil/internal/common"
	"golang.org/x/crypto/ssh"
)

type LSB struct {
	ID          string
	Release     string
	Codename    string
	Description string
}

// from utmp.h
const USER_PROCESS = 7

func Info(sshClient *ssh.Client, sftpClient *sftp.Client) (*InfoStat, error) {
	return InfoWithContext(context.Background(), sshClient, sftpClient)
}

func InfoWithContext(ctx context.Context, sshClient *ssh.Client, sftpClient *sftp.Client) (*InfoStat, error) {
	ret := &InfoStat{
		OS: runtime.GOOS,
	}
	hostname, err := common.RemoteReadFile(sftpClient, "/etc/hostname")
	if err == nil {
		ret.Hostname = string(bytes.TrimSpace(hostname))
	}

	platform, family, version, err := PlatformInformation(sshClient, sftpClient)
	if err == nil {
		ret.Platform = platform
		ret.PlatformFamily = family
		ret.PlatformVersion = version
	}
	kernelVersion, err := KernelVersion(sftpClient)
	if err == nil {
		ret.KernelVersion = kernelVersion
	}

	system, role, err := Virtualization(sftpClient)
	if err == nil {
		ret.VirtualizationSystem = system
		ret.VirtualizationRole = role
	}

	boot, err := BootTime(sftpClient)
	if err == nil {
		ret.BootTime = boot
		ret.Uptime = uptime(boot)
	}

	if numProcs, err := common.RemoteLinuxNumProcs(sftpClient); err == nil {
		ret.Procs = numProcs
	}

	sysProductUUID := common.HostSys("class/dmi/id/product_uuid")
	machineID := common.HostEtc("machine-id")
	procSysKernelRandomBootID := common.HostProc("sys/kernel/random/boot_id")
	existsProduct, err := common.RemotePathExists(sftpClient, sysProductUUID)
	if err != nil {
		return nil, err
	}
	existsMachine, err := common.RemotePathExists(sftpClient, machineID)
	if err != nil {
		return nil, err
	}
	switch {
	// In order to read this file, needs to be supported by kernel/arch and run as root
	// so having fallback is important
	case existsProduct:
		lines, err := common.RemoteReadLines(sftpClient, sysProductUUID)
		if err == nil && len(lines) > 0 && lines[0] != "" {
			ret.HostID = strings.ToLower(lines[0])
			break
		}
		fallthrough
	// Fallback on GNU Linux systems with systemd, readable by everyone
	case existsMachine:
		lines, err := common.RemoteReadLines(sftpClient, machineID)
		if err == nil && len(lines) > 0 && len(lines[0]) == 32 {
			st := lines[0]
			ret.HostID = fmt.Sprintf("%s-%s-%s-%s-%s", st[0:8], st[8:12], st[12:16], st[16:20], st[20:32])
			break
		}
		fallthrough
	// Not stable between reboot, but better than nothing
	default:
		lines, err := common.RemoteReadLines(sftpClient, procSysKernelRandomBootID)
		if err == nil && len(lines) > 0 && lines[0] != "" {
			ret.HostID = strings.ToLower(lines[0])
		}
	}

	return ret, nil
}

// cachedBootTime must be accessed via atomic.Load/StoreUint64
var cachedBootTime uint64

// BootTime returns the system boot time expressed in seconds since the epoch.
func BootTime(client *sftp.Client) (uint64, error) {
	return BootTimeWithContext(context.Background(), client)
}

func BootTimeWithContext(ctx context.Context, client *sftp.Client) (uint64, error) {
	t := atomic.LoadUint64(&cachedBootTime)
	if t != 0 {
		return t, nil
	}

	system, role, err := Virtualization(client)
	if err != nil {
		return 0, err
	}

	statFile := "stat"
	if system == "lxc" && role == "guest" {
		// if lxc, /proc/uptime is used.
		statFile = "uptime"
	} else if system == "docker" && role == "guest" {
		// also docker, guest
		statFile = "uptime"
	}

	filename := common.HostProc(statFile)
	lines, err := common.RemoteReadLines(client, filename)
	if err != nil {
		return 0, err
	}

	if statFile == "stat" {
		for _, line := range lines {
			if strings.HasPrefix(line, "btime") {
				f := strings.Fields(line)
				if len(f) != 2 {
					return 0, fmt.Errorf("wrong btime format")
				}
				b, err := strconv.ParseInt(f[1], 10, 64)
				if err != nil {
					return 0, err
				}
				t = uint64(b)
				atomic.StoreUint64(&cachedBootTime, t)
				return t, nil
			}
		}
	} else if statFile == "uptime" {
		if len(lines) != 1 {
			return 0, fmt.Errorf("wrong uptime format")
		}
		f := strings.Fields(lines[0])
		b, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			return 0, err
		}
		t = uint64(time.Now().Unix()) - uint64(b)
		atomic.StoreUint64(&cachedBootTime, t)
		return t, nil
	}

	return 0, fmt.Errorf("could not find btime")
}

func uptime(boot uint64) uint64 {
	return uint64(time.Now().Unix()) - boot
}

func Uptime(client *sftp.Client) (uint64, error) {
	return UptimeWithContext(context.Background(), client)
}

func UptimeWithContext(ctx context.Context, client *sftp.Client) (uint64, error) {
	boot, err := BootTime(client)
	if err != nil {
		return 0, err
	}
	return uptime(boot), nil
}

func Users(client *sftp.Client) ([]UserStat, error) {
	return UsersWithContext(context.Background(), client)
}

func UsersWithContext(ctx context.Context, client *sftp.Client) ([]UserStat, error) {
	utmpfile := common.HostVar("run/utmp")

	file, err := client.Open(utmpfile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	count := len(buf) / sizeOfUtmp

	ret := make([]UserStat, 0, count)

	for i := 0; i < count; i++ {
		b := buf[i*sizeOfUtmp : (i+1)*sizeOfUtmp]

		var u utmp
		br := bytes.NewReader(b)
		err := binary.Read(br, binary.LittleEndian, &u)
		if err != nil {
			continue
		}
		if u.Type != USER_PROCESS {
			continue
		}
		user := UserStat{
			User:     common.IntToString(u.User[:]),
			Terminal: common.IntToString(u.Line[:]),
			Host:     common.IntToString(u.Host[:]),
			Started:  int(u.Tv.Sec),
		}
		ret = append(ret, user)
	}

	return ret, nil

}

func getOSRelease(client *sftp.Client) (platform string, version string, err error) {
	contents, err := common.RemoteReadLines(client, common.HostEtc("os-release"))
	if err != nil {
		return "", "", err
	}
	for _, line := range contents {
		field := strings.Split(line, "=")
		if len(field) < 2 {
			continue
		}
		switch field[0] {
		case "ID": // use ID for lowercase
			platform = field[1]
		case "VERSION":
			version = field[1]
		}
	}
	return platform, version, nil
}

func getLSB(sshClient *ssh.Client, sftpClient *sftp.Client) (*LSB, error) {
	ret := &LSB{}
	exists, err := common.RemotePathExists(sftpClient, common.HostEtc("lsb-release"))
	if err != nil {
		return nil, err
	}
	if exists {
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("lsb-release"))
		if err != nil {
			return ret, err // return empty
		}
		for _, line := range contents {
			field := strings.Split(line, "=")
			if len(field) < 2 {
				continue
			}
			switch field[0] {
			case "DISTRIB_ID":
				ret.ID = field[1]
			case "DISTRIB_RELEASE":
				ret.Release = field[1]
			case "DISTRIB_CODENAME":
				ret.Codename = field[1]
			case "DISTRIB_DESCRIPTION":
				ret.Description = field[1]
			}
		}
	} else {
		exists, err := common.RemotePathExists(sftpClient, "/usr/bin/lsb_release")
		if err != nil {
			return nil, err
		}
		if exists {
			invoker := common.RemoteInvoke{Client: sshClient}
			out, err := invoker.Command("lsb_release")
			if err != nil {
				return ret, err
			}
			for _, line := range strings.Split(string(out), "\n") {
				field := strings.Split(line, ":")
				if len(field) < 2 {
					continue
				}
				switch field[0] {
				case "Distributor ID":
					ret.ID = field[1]
				case "Release":
					ret.Release = field[1]
				case "Codename":
					ret.Codename = field[1]
				case "Description":
					ret.Description = field[1]
				}
			}
		}
	}

	return ret, nil
}

func PlatformInformation(sshClient *ssh.Client, sftpClient *sftp.Client) (platform string, family string, version string, err error) {
	return PlatformInformationWithContext(context.Background(), sshClient, sftpClient)
}

func PlatformInformationWithContext(ctx context.Context, sshClient *ssh.Client, sftpClient *sftp.Client) (platform string, family string, version string, err error) {

	lsb, err := getLSB(sshClient, sftpClient)
	if err != nil {
		lsb = &LSB{}
	}

	if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("oracle-release")); err == nil && exists {
		platform = "oracle"
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("oracle-release"))
		if err == nil {
			version = getRedhatishVersion(contents)
		}

	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("enterprise-release")); err == nil && exists {
		platform = "oracle"
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("enterprise-release"))
		if err == nil {
			version = getRedhatishVersion(contents)
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("slackware-version")); err == nil && exists {
		platform = "slackware"
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("slackware-version"))
		if err == nil {
			version = getSlackwareVersion(contents)
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("debian_version")); err == nil && exists {
		if lsb.ID == "Ubuntu" {
			platform = "ubuntu"
			version = lsb.Release
		} else if lsb.ID == "LinuxMint" {
			platform = "linuxmint"
			version = lsb.Release
		} else {
			if exists, err := common.RemotePathExists(sftpClient, "/usr/bin/raspi-config"); err == nil && exists {
				platform = "raspbian"
			} else {
				platform = "debian"
			}
			contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("debian_version"))
			if err == nil {
				version = contents[0]
			}
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("redhat-release")); err == nil && exists {
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("redhat-release"))
		if err == nil {
			version = getRedhatishVersion(contents)
			platform = getRedhatishPlatform(contents)
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("system-release")); err == nil && exists {
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("system-release"))
		if err == nil {
			version = getRedhatishVersion(contents)
			platform = getRedhatishPlatform(contents)
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("gentoo-release")); err == nil && exists {
		platform = "gentoo"
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("gentoo-release"))
		if err == nil {
			version = getRedhatishVersion(contents)
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("SuSE-release")); err == nil && exists {
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("SuSE-release"))
		if err == nil {
			version = getSuseVersion(contents)
			platform = getSusePlatform(contents)
		}
		// TODO: slackware detecion
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("arch-release")); err == nil && exists {
		platform = "arch"
		version = lsb.Release
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("alpine-release")); err == nil && exists {
		platform = "alpine"
		contents, err := common.RemoteReadLines(sftpClient, common.HostEtc("alpine-release"))
		if err == nil && len(contents) > 0 {
			version = contents[0]
		}
	} else if exists, err := common.RemotePathExists(sftpClient, common.HostEtc("os-release")); err == nil && exists {
		p, v, err := getOSRelease(sftpClient)
		if err == nil {
			platform = p
			version = v
		}
	} else if lsb.ID == "RedHat" {
		platform = "redhat"
		version = lsb.Release
	} else if lsb.ID == "Amazon" {
		platform = "amazon"
		version = lsb.Release
	} else if lsb.ID == "ScientificSL" {
		platform = "scientific"
		version = lsb.Release
	} else if lsb.ID == "XenServer" {
		platform = "xenserver"
		version = lsb.Release
	} else if lsb.ID != "" {
		platform = strings.ToLower(lsb.ID)
		version = lsb.Release
	}

	switch platform {
	case "debian", "ubuntu", "linuxmint", "raspbian":
		family = "debian"
	case "fedora":
		family = "fedora"
	case "oracle", "centos", "redhat", "scientific", "enterpriseenterprise", "amazon", "xenserver", "cloudlinux", "ibm_powerkvm":
		family = "rhel"
	case "suse", "opensuse":
		family = "suse"
	case "gentoo":
		family = "gentoo"
	case "slackware":
		family = "slackware"
	case "arch":
		family = "arch"
	case "exherbo":
		family = "exherbo"
	case "alpine":
		family = "alpine"
	case "coreos":
		family = "coreos"
	}

	return platform, family, version, nil

}

func KernelVersion(client *sftp.Client) (version string, err error) {
	return KernelVersionWithContext(context.Background(), client)
}

func KernelVersionWithContext(ctx context.Context, client *sftp.Client) (version string, err error) {
	filename := common.HostProc("sys/kernel/osrelease")
	exists, err := common.RemotePathExists(client, filename)
	if err != nil {
		return "", err
	}
	if exists {
		contents, err := common.RemoteReadLines(client, filename)
		if err != nil {
			return "", err
		}

		if len(contents) > 0 {
			version = contents[0]
		}
	}
	return version, nil
}

func getSlackwareVersion(contents []string) string {
	c := strings.ToLower(strings.Join(contents, ""))
	c = strings.Replace(c, "slackware ", "", 1)
	return c
}

func getRedhatishVersion(contents []string) string {
	c := strings.ToLower(strings.Join(contents, ""))

	if strings.Contains(c, "rawhide") {
		return "rawhide"
	}
	if matches := regexp.MustCompile(`release (\d[\d.]*)`).FindStringSubmatch(c); matches != nil {
		return matches[1]
	}
	return ""
}

func getRedhatishPlatform(contents []string) string {
	c := strings.ToLower(strings.Join(contents, ""))

	if strings.Contains(c, "red hat") {
		return "redhat"
	}
	f := strings.Split(c, " ")

	return f[0]
}

func getSuseVersion(contents []string) string {
	version := ""
	for _, line := range contents {
		if matches := regexp.MustCompile(`VERSION = ([\d.]+)`).FindStringSubmatch(line); matches != nil {
			version = matches[1]
		} else if matches := regexp.MustCompile(`PATCHLEVEL = ([\d]+)`).FindStringSubmatch(line); matches != nil {
			version = version + "." + matches[1]
		}
	}
	return version
}

func getSusePlatform(contents []string) string {
	c := strings.ToLower(strings.Join(contents, ""))
	if strings.Contains(c, "opensuse") {
		return "opensuse"
	}
	return "suse"
}

func Virtualization(client *sftp.Client) (string, string, error) {
	return VirtualizationWithContext(context.Background(), client)
}

func VirtualizationWithContext(ctx context.Context, client *sftp.Client) (string, string, error) {
	var system string
	var role string

	filename := common.HostProc("xen")
	exists, err := common.RemotePathExists(client, filename)
	if err != nil {
		return "", "", err
	}
	if exists {
		system = "xen"
		role = "guest" // assume guest
		exists, err := common.RemotePathExists(client, filepath.Join(filename, "capabilities"))
		if err != nil {
			return "", "", err
		}
		if exists {
			contents, err := common.RemoteReadLines(client, filepath.Join(filename, "capabilities"))
			if err != nil {
				return "", "", err
			}
			if common.StringsContains(contents, "control_d") {
				role = "host"
			}
		}
	}

	filename = common.HostProc("modules")
	exists, err = common.RemotePathExists(client, filename)
	if err != nil {
		return "", "", err
	}
	if exists {
		contents, err := common.RemoteReadLines(client, filename)
		if err != nil {
			return "", "", err
		}
		if common.StringsContains(contents, "kvm") {
			system = "kvm"
			role = "host"
		} else if common.StringsContains(contents, "vboxdrv") {
			system = "vbox"
			role = "host"
		} else if common.StringsContains(contents, "vboxguest") {
			system = "vbox"
			role = "guest"
		} else if common.StringsContains(contents, "vmware") {
			system = "vmware"
			role = "guest"
		}
	}

	filename = common.HostProc("cpuinfo")
	exists, err = common.RemotePathExists(client, filename)
	if err != nil {
		return "", "", err
	}
	if exists {
		contents, err := common.RemoteReadLines(client, filename)
		if err != nil {
			return "", "", err
		}
		if common.StringsContains(contents, "QEMU Virtual CPU") ||
			common.StringsContains(contents, "Common KVM processor") ||
			common.StringsContains(contents, "Common 32-bit KVM processor") {
			system = "kvm"
			role = "guest"
		}
	}

	filename = common.HostProc()
	exists, err = common.RemotePathExists(client, filepath.Join(filename, "bc", "0"))
	if err != nil {
		return "", "", err
	}
	if exists {
		system = "openvz"
		role = "host"
	} else {
		exists, err := common.RemotePathExists(client, filepath.Join(filename, "vz"))
		if err != nil {
			return "", "", err
		}
		if exists {
			system = "openvz"
			role = "guest"
		}
	}
	// not use dmidecode because it requires root
	exists, err = common.RemotePathExists(client, filepath.Join(filename, "self", "status"))
	if err != nil {
		return "", "", err
	}
	if exists {
		contents, err := common.RemoteReadLines(client, filepath.Join(filename, "self", "status"))
		if err != nil {
			return "", "", err
		}
		if common.StringsContains(contents, "s_context:") ||
			common.StringsContains(contents, "VxID:") {
			system = "linux-vserver"
		}
		// TODO: guest or host
	}

	exists, err = common.RemotePathExists(client, filepath.Join(filename, "self", "cgroup"))
	if err != nil {
		return "", "", err
	}
	if exists {
		contents, err := common.RemoteReadLines(client, filepath.Join(filename, "self", "cgroup"))
		if err != nil {
			return "", "", err
		}
		if common.StringsContains(contents, "lxc") {
			system = "lxc"
			role = "guest"
		} else if common.StringsContains(contents, "docker") {
			system = "docker"
			role = "guest"
		} else if common.StringsContains(contents, "machine-rkt") {
			system = "rkt"
			role = "guest"
		} else if common.PathExists("/usr/bin/lxc-version") {
			system = "lxc"
			role = "host"
		}
	}

	exists, err = common.RemotePathExists(client, common.HostEtc("os-release"))
	if err != nil {
		return "", "", err
	}
	if exists {
		p, _, err := getOSRelease(client)
		if err != nil {
			return "", "", err
		}
		if p == "coreos" {
			system = "rkt" // Is it true?
			role = "host"
		}
	}
	return system, role, nil
}

func SensorsTemperatures(client *sftp.Client) ([]TemperatureStat, error) {
	return SensorsTemperaturesWithContext(context.Background(), client)
}

func SensorsTemperaturesWithContext(ctx context.Context, client *sftp.Client) ([]TemperatureStat, error) {
	var temperatures []TemperatureStat
	files, err := common.Glob(client, common.HostSys("/class/hwmon/hwmon*/temp*_*"))
	if err != nil {
		return temperatures, err
	}
	if len(files) == 0 {
		// CentOS has an intermediate /device directory:
		// https://github.com/giampaolo/psutil/issues/971
		files, err = common.Glob(client, common.HostSys("/class/hwmon/hwmon*/device/temp*_*"))
		if err != nil {
			return temperatures, err
		}
	}

	// example directory
	// device/           temp1_crit_alarm  temp2_crit_alarm  temp3_crit_alarm  temp4_crit_alarm  temp5_crit_alarm  temp6_crit_alarm  temp7_crit_alarm
	// name              temp1_input       temp2_input       temp3_input       temp4_input       temp5_input       temp6_input       temp7_input
	// power/            temp1_label       temp2_label       temp3_label       temp4_label       temp5_label       temp6_label       temp7_label
	// subsystem/        temp1_max         temp2_max         temp3_max         temp4_max         temp5_max         temp6_max         temp7_max
	// temp1_crit        temp2_crit        temp3_crit        temp4_crit        temp5_crit        temp6_crit        temp7_crit        uevent
	for _, file := range files {
		filename := strings.Split(filepath.Base(file), "_")
		if filename[1] == "label" {
			// Do not try to read the temperature of the label file
			continue
		}

		// Get the label of the temperature you are reading
		var label string
		c, _ := common.RemoteReadFile(client, filepath.Join(filepath.Dir(file), filename[0]+"_label"))
		if c != nil {
			//format the label from "Core 0" to "core0_"
			label = fmt.Sprintf("%s_", strings.Join(strings.Split(strings.TrimSpace(strings.ToLower(string(c))), " "), ""))
		}

		// Get the name of the temperature you are reading
		name, err := common.RemoteReadFile(client, filepath.Join(filepath.Dir(file), "name"))
		if err != nil {
			return temperatures, err
		}

		// Get the temperature reading
		current, err := common.RemoteReadFile(client, file)
		if err != nil {
			return temperatures, err
		}
		temperature, err := strconv.ParseFloat(strings.TrimSpace(string(current)), 64)
		if err != nil {
			continue
		}

		tempName := strings.TrimSpace(strings.ToLower(strings.Join(filename[1:], "")))
		temperatures = append(temperatures, TemperatureStat{
			SensorKey:   fmt.Sprintf("%s_%s%s", strings.TrimSpace(string(name)), label, tempName),
			Temperature: temperature / 1000.0,
		})
	}
	return temperatures, nil
}
