package battery

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
)

// State type enumerates possible battery states.
type State int

// Possible state values.
// Unknown can mean either controller returned unknown, or
// not able to retrieve state due to some error.
const (
	Unknown State = iota
	Empty
	Full
	Charging
	Discharging
)

var states = [...]string{
	Unknown:     "Unknown",
	Empty:       "Empty",
	Full:        "Full",
	Charging:    "Charging",
	Discharging: "Discharging",
}

func (s State) String() string {
	return states[s]
}

func newState(name string) (State, error) {
	for i, state := range states {
		if strings.EqualFold(name, state) {
			return State(i), nil
		}
	}
	return Unknown, fmt.Errorf("Invalid state `%s`", name)
}

// Battery type represents a single battery entry information.
type Battery struct {
	// Current battery state.
	State State
	// Current (momentary) capacity (in mWh).
	Current float64
	// Last known full capacity (in mWh).
	Full float64
	// Reported design capacity (in mWh).
	Design float64
	// Current (momentary) charge rate (in mW).
	// It is always non-negative, consult .State field to check
	// whether it means charging or discharging.
	ChargeRate float64
	// Current voltage (in V).
	Voltage float64
	// Design voltage (in V).
	// Some systems (e.g. macOS) do not provide a separate
	// value for this. In such cases, or if getting this fails,
	// but getting `Voltage` succeeds, this field will have
	// the same value as `Voltage`, for convenience.
	DesignVoltage float64
}

func (b *Battery) String() string {
	return fmt.Sprintf("%+v", *b)
}

// Get returns battery information for given index.
//
// Note that index taken here is normalized, such that GetAll()[idx] == Get(idx).
// It does not necessarily represent the "name" or "position" a battery was given
// by the underlying system.
//
// If error != nil, it will be either ErrFatal or ErrPartial.
func Get(c *sftp.Client, idx int) (*Battery, error) {
	b, err := systemGet(c, idx)
	return b, wrapError(err)
}

func getAll(c *sftp.Client, sg func(*sftp.Client) ([]*Battery, error)) ([]*Battery, error) {
	bs, err := sg(c)
	if errors, ok := err.(Errors); ok {
		nils := 0
		partials := 0
		for i, err := range errors {
			err = wrapError(err)
			if err == nil {
				nils++
			}
			if _, ok := err.(ErrPartial); ok {
				partials++
			}
			errors[i] = err
		}
		if nils == len(errors) {
			return bs, nil
		}
		if nils > 0 || partials > 0 {
			return bs, errors
		}
		return nil, ErrFatal{ErrAllNotNil}
	}
	if err != nil {
		return bs, ErrFatal{err}
	}
	return bs, nil
}

// GetAll returns information about all batteries in the system.
//
// If error != nil, it will be either ErrFatal or Errors.
// If error is of type Errors, it is guaranteed that length of both returned slices is the same and that i-th error coresponds with i-th battery structure.
func GetAll(c *sftp.Client) ([]*Battery, error) {
	return getAll(c, systemGetAll)
}

const sysfs = "/sys/class/power_supply"

func readFloat(path, filename string) (float64, error) {
	str, err := ioutil.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return 0, err
	}
	num, err := strconv.ParseFloat(string(str[:len(str)-1]), 64)
	if err != nil {
		return 0, err
	}
	return num / 1000, nil // Convert micro->milli
}

func readAmp(path, filename string, volts float64) (float64, error) {
	val, err := readFloat(path, filename)
	if err != nil {
		return 0, err
	}
	return val * volts, nil
}

func isBattery(path string) bool {
	t, err := ioutil.ReadFile(filepath.Join(path, "type"))
	return err == nil && string(t) == "Battery\n"
}

func getBatteryFiles(c *sftp.Client) ([]string, error) {
	files, err := c.ReadDir(sysfs)
	if err != nil {
		return nil, err
	}

	var bFiles []string
	for _, file := range files {
		path := filepath.Join(sysfs, file.Name())
		if isBattery(path) {
			bFiles = append(bFiles, path)
		}
	}
	return bFiles, nil
}

func getByPath(path string) (*Battery, error) {
	b := &Battery{}
	e := ErrPartial{}
	b.Current, e.Current = readFloat(path, "energy_now")
	b.Voltage, e.Voltage = readFloat(path, "voltage_now")
	b.Voltage /= 1000

	b.DesignVoltage, e.DesignVoltage = readFloat(path, "voltage_max_design")
	if e.DesignVoltage != nil {
		b.DesignVoltage, e.DesignVoltage = readFloat(path, "voltage_min_design")
	}
	if e.DesignVoltage != nil && e.Voltage == nil {
		b.DesignVoltage, e.DesignVoltage = b.Voltage, nil
	}
	b.DesignVoltage /= 1000

	if os.IsNotExist(e.Current) {
		if e.DesignVoltage == nil {
			b.Design, e.Design = readAmp(path, "charge_full_design", b.DesignVoltage)
		} else {
			e.Design = e.DesignVoltage
		}
		if e.Voltage == nil {
			b.Current, e.Current = readAmp(path, "charge_now", b.Voltage)
			b.Full, e.Full = readAmp(path, "charge_full", b.Voltage)
			b.ChargeRate, e.ChargeRate = readAmp(path, "current_now", b.Voltage)
		} else {
			e.Current = e.Voltage
			e.Full = e.Voltage
			e.ChargeRate = e.Voltage
		}
	} else {
		b.Full, e.Full = readFloat(path, "energy_full")
		b.Design, e.Design = readFloat(path, "energy_full_design")
		b.ChargeRate, e.ChargeRate = readFloat(path, "power_now")
	}
	state, err := ioutil.ReadFile(filepath.Join(path, "status"))
	if err == nil {
		b.State, e.State = newState(string(state[:len(state)-1]))
	} else {
		e.State = err
	}

	return b, e
}

func systemGet(c *sftp.Client, idx int) (*Battery, error) {
	bFiles, err := getBatteryFiles(c)
	if err != nil {
		return nil, err
	}

	if idx >= len(bFiles) {
		return nil, ErrNotFound
	}
	return getByPath(bFiles[idx])
}

func systemGetAll(c *sftp.Client) ([]*Battery, error) {
	bFiles, err := getBatteryFiles(c)
	if err != nil {
		return nil, err
	}

	batteries := make([]*Battery, len(bFiles))
	errors := make(Errors, len(bFiles))
	for i, bFile := range bFiles {
		battery, err := getByPath(bFile)
		batteries[i] = battery
		errors[i] = err
	}

	return batteries, errors
}

var ErrNotFound = fmt.Errorf("Not found")

// ErrAllNotNil variable says that backend returned ErrPartial with
// all fields having not nil values, hence it was converted to ErrFatal.
//
// Only ever returned wrapped in ErrFatal.
var ErrAllNotNil = fmt.Errorf("All fields had not nil errors")

// ErrFatal type represents a fatal error.
//
// It indicates that either the library was not able to perform some kind
// of operation critical to retrieving any data, or all partials have failed at
// once (which would be equivalent to returning a ErrPartial with no nils).
//
// As such, the caller should assume that no meaningful data was
// returned alongside the error and act accordingly.
type ErrFatal struct {
	Err error // The actual error that happened.
}

func (f ErrFatal) Error() string {
	return fmt.Sprintf("Could not retrieve battery info: `%s`", f.Err)
}

// ErrPartial type represents a partial error.
//
// It indicates that there were problems retrieving some of the data,
// but some was also retrieved successfully.
// If there would be all nils, nil is returned instead.
// If there would be all not nils, ErrFatal is returned instead.
//
// The fields represent fields in the Battery type.
type ErrPartial struct {
	State         error
	Current       error
	Full          error
	Design        error
	ChargeRate    error
	Voltage       error
	DesignVoltage error
}

func (p ErrPartial) Error() string {
	if p.isNil() {
		return "{}"
	}
	errors := map[string]error{
		"State":         p.State,
		"Current":       p.Current,
		"Full":          p.Full,
		"Design":        p.Design,
		"ChargeRate":    p.ChargeRate,
		"Voltage":       p.Voltage,
		"DesignVoltage": p.DesignVoltage,
	}
	keys := []string{"State", "Current", "Full", "Design", "ChargeRate", "Voltage", "DesignVoltage"}
	s := "{"
	for _, name := range keys {
		err := errors[name]
		if err != nil {
			s += fmt.Sprintf("%s:%s ", name, err.Error())
		}
	}
	return s[:len(s)-1] + "}"
}

func (p ErrPartial) isNil() bool {
	return p.State == nil &&
		p.Current == nil &&
		p.Full == nil &&
		p.Design == nil &&
		p.ChargeRate == nil &&
		p.Voltage == nil &&
		p.DesignVoltage == nil
}

func (p ErrPartial) noNil() bool {
	return p.State != nil &&
		p.Current != nil &&
		p.Full != nil &&
		p.Design != nil &&
		p.ChargeRate != nil &&
		p.Voltage != nil &&
		p.DesignVoltage != nil
}

// Errors type represents an array of ErrFatal, ErrPartial or nil values.
//
// Can only possibly be returned by GetAll() call.
type Errors []error

func (e Errors) Error() string {
	s := "["
	for _, err := range e {
		if err != nil {
			s += err.Error() + " "
		}
	}
	if len(s) > 1 {
		s = s[:len(s)-1]
	}
	return s + "]"
}

func wrapError(err error) error {
	if perr, ok := err.(ErrPartial); ok {
		if perr.isNil() {
			return nil
		}
		if perr.noNil() {
			return ErrFatal{ErrAllNotNil}
		}
		return perr
	}
	if err != nil {
		return ErrFatal{err}
	}
	return nil
}
