#!/bin/sh
set -e
rm -rf manpages
mkdir manpages
go run . man | gzip -c > "manpages/infisical.1.gz"