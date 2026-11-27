package util

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

const (
	DevicePlatformMacOS   = "macos"
	DevicePlatformWindows = "windows"
	DevicePlatformLinux   = "linux"
)

const linuxSerialPath = "/sys/class/dmi/id/product_serial"

type DeviceInfoError struct {
	Message string
	Cause   error
}

func (e *DeviceInfoError) Error() string { return e.Message }

func (e *DeviceInfoError) Unwrap() error { return e.Cause }

var (
	runDeviceCommand = func(name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, name, args...).Output()
		return string(out), err
	}
	readDeviceFile = os.ReadFile
	deviceHostname = os.Hostname
	deviceGOOS     = runtime.GOOS
)

// CollectDeviceInfo reads the hardware serial number and display details of this machine. Only the
// serial number is required; everything else is best effort.
func CollectDeviceInfo() (api.PAMDeviceInfo, error) {
	var info api.PAMDeviceInfo
	var err error
	switch deviceGOOS {
	case "darwin":
		info, err = collectMacOSDeviceInfo()
	case "windows":
		info, err = collectWindowsDeviceInfo()
	case "linux":
		info, err = collectLinuxDeviceInfo()
	default:
		return api.PAMDeviceInfo{}, &DeviceInfoError{Message: fmt.Sprintf("Device checks aren't supported on %s. Use a macOS, Windows or Linux device.", deviceGOOS)}
	}
	if err != nil {
		return api.PAMDeviceInfo{}, err
	}
	if hostname, hostErr := deviceHostname(); hostErr == nil {
		info.Hostname = strings.TrimSpace(hostname)
	}
	return info, nil
}

func collectMacOSDeviceInfo() (api.PAMDeviceInfo, error) {
	out, err := runDeviceCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return api.PAMDeviceInfo{}, &DeviceInfoError{Cause: err,
			Message: fmt.Sprintf("Couldn't read this Mac's serial number: running ioreg failed (%v). Check that /usr/sbin/ioreg is on PATH and try again.", err)}
	}
	serial, model := parseIORegPlatformDevice(out)
	if serial == "" {
		return api.PAMDeviceInfo{}, &DeviceInfoError{Message: "Couldn't read this Mac's serial number: ioreg didn't report IOPlatformSerialNumber."}
	}
	info := api.PAMDeviceInfo{SerialNumber: serial, Platform: DevicePlatformMacOS, Model: model, OSName: "macOS"}
	if version, versionErr := runDeviceCommand("sw_vers", "-productVersion"); versionErr == nil {
		info.OSVersion = strings.TrimSpace(version)
	}
	return info, nil
}

var (
	ioregSerialPattern = regexp.MustCompile(`"IOPlatformSerialNumber"\s*=\s*"([^"]*)"`)
	ioregModelPattern  = regexp.MustCompile(`"model"\s*=\s*<"([^"]*)">`)
)

func parseIORegPlatformDevice(out string) (serial, model string) {
	if match := ioregSerialPattern.FindStringSubmatch(out); match != nil {
		serial = cleanSerial(match[1])
	}
	if match := ioregModelPattern.FindStringSubmatch(out); match != nil {
		model = strings.TrimSpace(match[1])
	}
	return serial, model
}

const windowsDeviceScript = `$b = Get-CimInstance Win32_BIOS; $c = Get-CimInstance Win32_ComputerSystem; $o = Get-CimInstance Win32_OperatingSystem; "serial=$($b.SerialNumber)"; "model=$($c.Model)"; "osName=$($o.Caption)"; "osVersion=$($o.Version)"`

func collectWindowsDeviceInfo() (api.PAMDeviceInfo, error) {
	out, err := runDeviceCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsDeviceScript)
	if err != nil {
		return api.PAMDeviceInfo{}, &DeviceInfoError{Cause: err,
			Message: fmt.Sprintf("Couldn't read this PC's serial number: running PowerShell failed (%v). Check that powershell.exe is on PATH and try again.", err)}
	}
	info := parseWindowsDeviceOutput(out)
	if info.SerialNumber == "" {
		return api.PAMDeviceInfo{}, &DeviceInfoError{Message: "Couldn't read this PC's serial number: Win32_BIOS has no serial number. Ask your IT team to check the device's BIOS."}
	}
	return info, nil
}

func parseWindowsDeviceOutput(out string) api.PAMDeviceInfo {
	info := api.PAMDeviceInfo{Platform: DevicePlatformWindows}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "serial":
			info.SerialNumber = cleanSerial(value)
		case "model":
			info.Model = value
		case "osName":
			info.OSName = strings.TrimPrefix(value, "Microsoft ")
		case "osVersion":
			info.OSVersion = value
		}
	}
	return info
}

func collectLinuxDeviceInfo() (api.PAMDeviceInfo, error) {
	raw, err := readDeviceFile(linuxSerialPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return api.PAMDeviceInfo{}, &DeviceInfoError{Cause: err,
				Message: fmt.Sprintf("Couldn't read this device's serial number: %s is readable only by root on most Linux systems. Ask your IT team to make it readable by your user, for example with a udev rule.", linuxSerialPath)}
		}
		return api.PAMDeviceInfo{}, &DeviceInfoError{Cause: err,
			Message: fmt.Sprintf("Couldn't read this device's serial number from %s (%v). Linux serial numbers may not be readable on virtual machines and some hardware.", linuxSerialPath, err)}
	}
	serial := cleanSerial(string(raw))
	if serial == "" {
		return api.PAMDeviceInfo{}, &DeviceInfoError{
			Message: fmt.Sprintf("Couldn't read this device's serial number: %s is empty or holds a placeholder. Linux serial numbers may not be readable on virtual machines and some hardware.", linuxSerialPath)}
	}

	info := api.PAMDeviceInfo{SerialNumber: serial, Platform: DevicePlatformLinux}
	if model, modelErr := readDeviceFile("/sys/class/dmi/id/product_name"); modelErr == nil {
		info.Model = strings.TrimSpace(string(model))
	}
	if release, releaseErr := readDeviceFile("/etc/os-release"); releaseErr == nil {
		info.OSName, info.OSVersion = parseOSRelease(string(release))
	}
	return info, nil
}

func parseOSRelease(content string) (name, version string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		key, value, found := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !found {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch key {
		case "NAME":
			name = value
		case "VERSION_ID":
			version = value
		}
	}
	return name, version
}

// Firmware that was never given a serial number reports one of these instead.
var placeholderSerials = map[string]bool{
	"":                       true,
	"0":                      true,
	"none":                   true,
	"n/a":                    true,
	"default string":         true,
	"to be filled by o.e.m.": true,
	"system serial number":   true,
	"not specified":          true,
	"not applicable":         true,
	"unknown":                true,
}

func cleanSerial(raw string) string {
	serial := strings.TrimSpace(strings.Trim(raw, "\x00"))
	if placeholderSerials[strings.ToLower(serial)] {
		return ""
	}
	return serial
}
