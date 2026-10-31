// Helper binary for integration testing of update hint path detection.
// Prints the update instruction for the current executable path and OS,
// without making any network calls.
package main

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/util"
)

func main() {
	fmt.Println(util.GetUpdateInstructions())
}
