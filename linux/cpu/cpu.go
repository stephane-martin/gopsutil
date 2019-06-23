package cpu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

// TimesStat contains the amounts of time the CPU has spent performing different
// kinds of work. Time units are in USER_HZ or Jiffies (typically hundredths of
// a second). It is based on linux /proc/stat file.
type TimesStat struct {
	CPU       string  `json:"cpu"`
	User      float64 `json:"user"`
	System    float64 `json:"system"`
	Idle      float64 `json:"idle"`
	Nice      float64 `json:"nice"`
	Iowait    float64 `json:"iowait"`
	Irq       float64 `json:"irq"`
	Softirq   float64 `json:"softirq"`
	Steal     float64 `json:"steal"`
	Guest     float64 `json:"guest"`
	GuestNice float64 `json:"guestNice"`
}

type InfoStat struct {
	CPU        int32    `json:"cpu"`
	VendorID   string   `json:"vendorId"`
	Family     string   `json:"family"`
	Model      string   `json:"model"`
	Stepping   int32    `json:"stepping"`
	PhysicalID string   `json:"physicalId"`
	CoreID     string   `json:"coreId"`
	Cores      int32    `json:"cores"`
	ModelName  string   `json:"modelName"`
	Mhz        float64  `json:"mhz"`
	CacheSize  int32    `json:"cacheSize"`
	Flags      []string `json:"flags"`
	Microcode  string   `json:"microcode"`
}

type lastPercent struct {
	sync.Mutex
	lastCPUTimes    []TimesStat
	lastPerCPUTimes []TimesStat
}

func (c TimesStat) String() string {
	v := []string{
		`"cpu":"` + c.CPU + `"`,
		`"user":` + strconv.FormatFloat(c.User, 'f', 1, 64),
		`"system":` + strconv.FormatFloat(c.System, 'f', 1, 64),
		`"idle":` + strconv.FormatFloat(c.Idle, 'f', 1, 64),
		`"nice":` + strconv.FormatFloat(c.Nice, 'f', 1, 64),
		`"iowait":` + strconv.FormatFloat(c.Iowait, 'f', 1, 64),
		`"irq":` + strconv.FormatFloat(c.Irq, 'f', 1, 64),
		`"softirq":` + strconv.FormatFloat(c.Softirq, 'f', 1, 64),
		`"steal":` + strconv.FormatFloat(c.Steal, 'f', 1, 64),
		`"guest":` + strconv.FormatFloat(c.Guest, 'f', 1, 64),
		`"guestNice":` + strconv.FormatFloat(c.GuestNice, 'f', 1, 64),
	}

	return `{` + strings.Join(v, ",") + `}`
}

// Total returns the total number of seconds in a CPUTimesStat
func (c TimesStat) Total() float64 {
	total := c.User + c.System + c.Nice + c.Iowait + c.Irq + c.Softirq + c.Steal +
		c.Guest + c.GuestNice + c.Idle
	return total
}

func (c InfoStat) String() string {
	s, _ := json.Marshal(c)
	return string(s)
}

func getAllBusy(t TimesStat) (float64, float64) {
	busy := t.User + t.System + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal + t.Guest + t.GuestNice
	return busy + t.Idle, busy
}

func calculateBusy(t1, t2 TimesStat) float64 {
	t1All, t1Busy := getAllBusy(t1)
	t2All, t2Busy := getAllBusy(t2)

	if t2Busy <= t1Busy {
		return 0
	}
	if t2All <= t1All {
		return 1
	}
	return (t2Busy - t1Busy) / (t2All - t1All) * 100
}

func calculateAllBusy(t1, t2 []TimesStat) ([]float64, error) {
	// Make sure the CPU measurements have the same length.
	if len(t1) != len(t2) {
		return nil, fmt.Errorf("received two CPU counts: %d != %d", len(t1), len(t2))
	}

	ret := make([]float64, len(t1))
	for i, t := range t2 {
		ret[i] = calculateBusy(t1[i], t)
	}
	return ret, nil
}

type PercentLast struct {
	client         *sftp.Client
	lastCPUPercent lastPercent
	c              *CPU
}

func (c *CPU) NewPercentLast() (*PercentLast, error) {
	var e1, e2 error
	p := new(PercentLast)
	p.lastCPUPercent.Lock()
	p.lastCPUPercent.lastCPUTimes, e1 = c.Times(false)
	p.lastCPUPercent.lastPerCPUTimes, e2 = c.Times(true)
	p.lastCPUPercent.Unlock()
	if e1 != nil {
		return nil, e1
	}
	if e2 != nil {
		return nil, e2
	}
	p.client = c.sftpClient
	p.c = c
	return p, nil
}

func (p *PercentLast) Next(percpu bool) ([]float64, error) {
	cpuTimes, err := p.c.Times(percpu)
	if err != nil {
		return nil, err
	}
	p.lastCPUPercent.Lock()
	defer p.lastCPUPercent.Unlock()
	var lastTimes []TimesStat
	if percpu {
		lastTimes = p.lastCPUPercent.lastPerCPUTimes
		p.lastCPUPercent.lastPerCPUTimes = cpuTimes
	} else {
		lastTimes = p.lastCPUPercent.lastCPUTimes
		p.lastCPUPercent.lastCPUTimes = cpuTimes
	}
	if lastTimes == nil {
		return nil, fmt.Errorf("error getting times for cpu percent. lastTimes was nil")
	}
	return calculateAllBusy(lastTimes, cpuTimes)
}

// Percent calculates the percentage of cpu used either per CPU or combined.
// If an interval of 0 is given it will compare the current cpu times against the last call.
// Returns one value per cpu, or a single value if percpu is set to false.
func (c *CPU) Percent(interval time.Duration, percpu bool) ([]float64, error) {
	return c.PercentWithContext(context.Background(), interval, percpu)
}

func (c *CPU) PercentWithContext(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error) {
	if interval <= 0 {
		return nil, errors.New("interval must be strictly positive")
	}
	// Get CPU usage at the start of the interval.
	cpuTimes1, err := c.Times(percpu)
	if err != nil {
		return nil, err
	}
	time.Sleep(interval)
	// And at the end of the interval.
	cpuTimes2, err := c.Times(percpu)
	if err != nil {
		return nil, err
	}
	return calculateAllBusy(cpuTimes1, cpuTimes2)
}