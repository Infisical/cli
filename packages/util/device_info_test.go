package util

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

const sampleIOReg = `+-o J516sAP  <class IOPlatformExpertDevice, id 0x100000215, registered, matched, active, busy 0 (2001 ms), retain 39>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "#address-cells" = <02000000>
      "model" = <"MacBookPro18,3">
      "IOPlatformSerialNumber" = "C02FX4ZHMD6R"
      "IOPlatformUUID" = "1B2C3D4E-0000-1111-2222-333344445555"
      "manufacturer" = <"Apple Inc.">
    }
`

func TestParseIORegPlatformDevice(t *testing.T) {
	serial, model := parseIORegPlatformDevice(sampleIOReg)
	if serial != "C02FX4ZHMD6R" || model != "MacBookPro18,3" {
		t.Errorf("got serial %q, model %q", serial, model)
	}

	serial, model = parseIORegPlatformDevice(`"model" = <4d6163>`)
	if serial != "" || model != "" {
		t.Errorf("expected nothing from output without a serial, got %q, %q", serial, model)
	}
}

func TestParseWindowsDeviceOutput(t *testing.T) {
	out := "serial=5CG1234XYZ\r\nmodel=HP EliteBook 840 G8\r\nosName=Microsoft Windows 11 Pro\r\nosVersion=10.0.22631\r\n"
	info := parseWindowsDeviceOutput(out)
	if info.SerialNumber != "5CG1234XYZ" || info.Model != "HP EliteBook 840 G8" || info.OSName != "Windows 11 Pro" || info.OSVersion != "10.0.22631" || info.Platform != DevicePlatformWindows {
		t.Errorf("unexpected %+v", info)
	}

	if got := parseWindowsDeviceOutput("serial=To be filled by O.E.M.\r\n").SerialNumber; got != "" {
		t.Errorf("placeholder serial kept: %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	name, version := parseOSRelease("PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n")
	if name != "Ubuntu" || version != "24.04" {
		t.Errorf("got %q %q", name, version)
	}
}

func withDeviceStubs(t *testing.T, goos string, command func(string, ...string) (string, error), files map[string]any) {
	t.Helper()
	oldRun, oldRead, oldHost, oldGOOS := runDeviceCommand, readDeviceFile, deviceHostname, deviceGOOS
	t.Cleanup(func() {
		runDeviceCommand, readDeviceFile, deviceHostname, deviceGOOS = oldRun, oldRead, oldHost, oldGOOS
	})
	deviceGOOS = goos
	runDeviceCommand = command
	readDeviceFile = func(path string) ([]byte, error) {
		switch v := files[path].(type) {
		case string:
			return []byte(v), nil
		case error:
			return nil, v
		}
		return nil, fs.ErrNotExist
	}
	deviceHostname = func() (string, error) { return "bernies-mbp", nil }
}

func TestCollectDeviceInfoMacOS(t *testing.T) {
	withDeviceStubs(t, "darwin", func(name string, _ ...string) (string, error) {
		if name == "sw_vers" {
			return "15.4.1\n", nil
		}
		return sampleIOReg, nil
	}, nil)
	info, err := CollectDeviceInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.SerialNumber != "C02FX4ZHMD6R" || info.Platform != DevicePlatformMacOS || info.OSName != "macOS" || info.OSVersion != "15.4.1" || info.Hostname != "bernies-mbp" {
		t.Errorf("unexpected %+v", info)
	}
}

func TestCollectDeviceInfoLinuxPermissionDenied(t *testing.T) {
	withDeviceStubs(t, "linux", nil, map[string]any{linuxSerialPath: fs.ErrPermission})
	_, err := CollectDeviceInfo()
	var infoErr *DeviceInfoError
	if !errors.As(err, &infoErr) || !strings.Contains(infoErr.Message, "sudo") {
		t.Errorf("expected a sudo hint, got %v", err)
	}
}

func TestCollectDeviceInfoLinux(t *testing.T) {
	withDeviceStubs(t, "linux", nil, map[string]any{
		linuxSerialPath:                  "PF3ABCDE\n",
		"/sys/class/dmi/id/product_name": "ThinkPad X1 Carbon Gen 11\n",
		"/etc/os-release":                "NAME=\"Fedora Linux\"\nVERSION_ID=40\n",
	})
	info, err := CollectDeviceInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.SerialNumber != "PF3ABCDE" || info.Model != "ThinkPad X1 Carbon Gen 11" || info.OSName != "Fedora Linux" || info.OSVersion != "40" {
		t.Errorf("unexpected %+v", info)
	}
}

func TestCollectDeviceInfoNoSerial(t *testing.T) {
	withDeviceStubs(t, "linux", nil, map[string]any{linuxSerialPath: "Default string\n"})
	if _, err := CollectDeviceInfo(); err == nil {
		t.Error("expected an error for a placeholder serial")
	}
	withDeviceStubs(t, "darwin", func(string, ...string) (string, error) { return "", errors.New("exec: not found") }, nil)
	if _, err := CollectDeviceInfo(); err == nil {
		t.Error("expected an error when ioreg fails")
	}
}
