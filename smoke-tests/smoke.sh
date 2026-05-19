#!/bin/sh
set -e

DISTRO="unknown"
if [ -f /etc/os-release ]; then
  DISTRO=$(. /etc/os-release && echo "$PRETTY_NAME")
fi

echo "=== CLI Smoke Tests ==="
echo "Distro: $DISTRO"
echo "Arch:   $(uname -m)"
echo ""

passed=0
failed=0

pass() {
  passed=$((passed + 1))
  echo "PASS: $1"
}

fail() {
  failed=$((failed + 1))
  echo "FAIL: $1"
}

if ! command -v infisical >/dev/null 2>&1; then
  fail "infisical binary not found in PATH"
  exit 1
fi
pass "binary found at $(command -v infisical)"

# --version
if output=$(infisical --version 2>&1); then
  pass "--version ($output)"
else
  fail "--version exited with $?"
fi

# --help
if infisical --help >/dev/null 2>&1; then
  pass "--help"
else
  fail "--help"
fi

# core subcommands
for cmd in secrets run export login agent gateway; do
  if infisical "$cmd" --help >/dev/null 2>&1; then
    pass "$cmd --help"
  else
    fail "$cmd --help"
  fi
done

# shared library check
BINARY_PATH=$(command -v infisical)
if command -v ldd >/dev/null 2>&1; then
  ldd_output=$(ldd "$BINARY_PATH" 2>&1 || true)
  if echo "$ldd_output" | grep -qi "not a dynamic executable\|statically linked\|not a valid dynamic program"; then
    pass "static binary (no dynamic dependencies)"
  elif echo "$ldd_output" | grep -qi "not found"; then
    fail "missing shared libraries"
    echo "$ldd_output"
  else
    pass "no missing shared libraries"
  fi
fi

echo ""
echo "Results: $passed passed, $failed failed"

if [ "$failed" -gt 0 ]; then
  exit 1
fi
