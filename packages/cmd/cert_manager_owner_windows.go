//go:build windows

package cmd

import "os"

func keepOwner(*os.File, os.FileInfo) error {
	return nil
}
