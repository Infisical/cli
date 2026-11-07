package webapp

import (
	"context"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/google/uuid"
)

type reapProbeDocker struct {
	dockerSpy
	probeSession  string
	orphanSession string
}

func (d *reapProbeDocker) Command(ctx context.Context, args ...string) (string, error) {
	if args[0] == "ps" {
		probe := "probe-container " + d.probeSession
		if strings.Contains(args[len(args)-1], "infisical.pam.probe") {
			probe += " 1"
		}
		return probe + "\norphan-container " + d.orphanSession + "\n", nil
	}
	return d.dockerSpy.Command(ctx, args...)
}

func TestReapSkipsRunningConnectionProbe(t *testing.T) {
	prior := session.GetSessionRecordingDir()
	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
	docker := &reapProbeDocker{probeSession: uuid.NewString(), orphanSession: uuid.NewString()}
	registry := NewRegistry("task-gateway", DefaultOptions(), nil, nil)
	registry.Docker = docker
	if err := registry.Reap(t.Context()); err != nil {
		t.Fatal(err)
	}
	orphanRemoved := false
	for _, args := range docker.commands {
		command := strings.Join(args, " ")
		if strings.Contains(command, "probe-container") || strings.Contains(command, docker.probeSession) {
			t.Fatalf("reaper touched an active probe: %v", args)
		}
		if command == "rm --force orphan-container" {
			orphanRemoved = true
		}
	}
	if !orphanRemoved {
		t.Fatal("ordinary orphan was not reaped")
	}
}
