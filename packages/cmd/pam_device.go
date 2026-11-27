package cmd

import (
	"regexp"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

var pamVerificationCodePattern = regexp.MustCompile(`^[A-Z0-9]{2,16}(?:-[A-Z0-9]{2,16})*$`)

var pamVerifyDeviceCmd = &cobra.Command{
	Use:   "verify-device <code>",
	Short: "Finish a device check started in the browser",
	Long: `Check this device against the device posture policy of a PAM account, to finish a check
started in the browser. The browser shows a code; run this command on the same device with that
code. The CLI reads this device's hardware serial number, and Infisical looks the device up in
your device management provider.

The code works once and expires after 5 minutes. On Linux, the serial number must be
readable by your user.`,
	Example:               `  infisical pam verify-device ABCD-EF23`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run:                   runPAMVerifyDevice,
}

func runPAMVerifyDevice(cmd *cobra.Command, args []string) {
	code := strings.ToUpper(strings.Join(strings.Fields(args[0]), ""))
	if len(code) == 8 && !strings.Contains(code, "-") {
		code = code[:4] + "-" + code[4:]
	}
	if !pamVerificationCodePattern.MatchString(code) {
		exitWithError(cmd, errPAMInvalidVerificationCode(args[0]))
	}

	device, err := util.CollectDeviceInfo()
	if err != nil {
		exitWithError(cmd, errPAMDeviceInfoUnavailable(err))
	}

	httpClient := newPAMHTTPClient(pamUserAccessToken(cmd))
	response, err := api.CallPAMCompleteDeviceVerification(httpClient, api.PAMCompleteDeviceVerificationRequest{Code: code, Device: device})
	if err != nil {
		if status, ok := pamVerificationCodeStatus(err); ok {
			exitWithError(cmd, errPAMVerificationCode(status, err))
		}
		exitWithError(cmd, classifyPAMAPIError(err, "", pamDeniedLaunch, false), "Failed to check this device")
	}

	verification := response.Verification
	header := pam.CheckingDeviceHeader(&verification, util.RedactCredentials(verification.AccountName))
	pam.PrintDeviceChecks(util.GetStdoutWriter(), header, &verification, device)

	if verification.Status == api.PAMDeviceVerificationError {
		exitWithError(cmd, errPAMDeviceCheckUnavailable(nil))
	}
	if verification.Status != api.PAMDeviceVerificationPassed {
		exitWithError(cmd, errPAMDeviceCheckFailed(nil))
	}
	util.PrintlnStdout("Device verified.")
	printProjectsTip(cmd, "Return to your browser to continue.")
}

func init() {
	pamCmd.AddCommand(pamVerifyDeviceCmd)
}
