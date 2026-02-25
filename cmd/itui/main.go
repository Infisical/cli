package main

import (
	"fmt"
	"os"

	"github.com/Infisical/infisical-merge/packages/itui"
)

func main() {
	if err := itui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
