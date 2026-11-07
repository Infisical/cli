package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/webapp"
	"github.com/spf13/cobra"
)

func browserWorkerCommand(shim bool) *cobra.Command {
	name := "browser-connector"
	if shim {
		name = "browser-shim"
	}
	var hard, lease int64
	var width, height int
	var leaseSeconds int
	var selfTest bool
	var probe string
	cmd := &cobra.Command{Use: name, Hidden: true, Short: "Run an isolated PAM browser worker", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if !shim && probe != "" {
			err := webapp.ProbeDestination(cmd.Context(), probe)
			result := webapp.ProbeResult{OK: err == nil}
			if err != nil {
				result.Message = err.Error()
			}
			if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
				return encodeErr
			}
			return err
		}
		if selfTest {
			hard = time.Now().Add(10 * time.Second).UnixMilli()
			lease = hard
		}
		if !selfTest && leaseSeconds >= 0 {
			if leaseSeconds > 45 {
				return fmt.Errorf("lease seconds exceed the maximum")
			}
			lease = time.Now().Add(time.Duration(leaseSeconds) * time.Second).UnixMilli()
		}
		if hard <= time.Now().UnixMilli() || lease <= time.Now().UnixMilli() {
			return fmt.Errorf("a live hard expiry and lease are required")
		}
		mux := webapp.NewMux(os.Stdin, os.Stdout)
		if shim {
			return webapp.RunShim(cmd.Context(), mux, time.UnixMilli(hard), time.UnixMilli(lease), width, height, selfTest)
		}
		return webapp.RunConnector(cmd.Context(), mux, "/run/pam/connector.sock", time.UnixMilli(hard), time.UnixMilli(lease))
	}}
	cmd.Flags().Int64Var(&hard, "hard-expiry", 0, "Hard session expiry as Unix milliseconds")
	cmd.Flags().Int64Var(&lease, "lease-until", 0, "Renewable lease deadline as Unix milliseconds")
	cmd.Flags().IntVar(&leaseSeconds, "lease-seconds", -1, "Relative lease remaining in seconds")
	if shim {
		cmd.Flags().IntVar(&width, "width", 1280, "Remote viewport width")
		cmd.Flags().IntVar(&height, "height", 720, "Remote viewport height")
		cmd.Flags().BoolVar(&selfTest, "self-test", false, "Verify the sandboxed browser and unreachable network")
	} else {
		cmd.Flags().StringVar(&probe, "probe", "", "Probe a policy-validated destination from the connector network")
	}
	return cmd
}

func init() { pamCmd.AddCommand(browserWorkerCommand(true), browserWorkerCommand(false)) }
