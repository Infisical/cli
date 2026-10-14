package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMonitorSecretChanges_ExecutesCommandOnInitialRender(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test command uses touch")
	}

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "secrets.env")
	markerPath := filepath.Join(tempDir, "command-ran")

	secretTemplate := Template{
		DestinationPath: outputPath,
		TemplateContent: "SECRET=value",
	}
	secretTemplate.Config.PollingInterval = "1ms"
	secretTemplate.Config.Execute.Command = fmt.Sprintf("touch %q", markerPath)

	manager := &AgentManager{
		accessToken:             "test-token",
		dynamicSecretLeases:     &DynamicSecretLeaseManager{},
		templateFirstRenderOnce: map[int]*sync.Once{1: {}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		manager.MonitorSecretChanges(ctx, secretTemplate, 1, make(chan os.Signal), make(chan bool, 1))
		close(done)
	}()

	deadline := time.After(time.Second)
	for {
		if _, err := os.Stat(markerPath); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("check command marker: %v", err)
		}

		select {
		case <-deadline:
			t.Fatal("execute command did not run after the initial render")
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("secret monitor did not stop after context cancellation")
	}
}
