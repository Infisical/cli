package webapp

import "os/exec"

func isolateProcess(cmd *exec.Cmd) {}
func killProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
