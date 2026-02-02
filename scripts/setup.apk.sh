#!/bin/sh
#
# Infisical CLI Alpine Repository Setup Script
# The core commands execute start from the "MAIN" section below.
#

set -e

# Environment variables that can be set
PKG_URL="${PKG_URL:-https://artifacts-cli.infisical.com}"
PACKAGE_NAME="${PACKAGE_NAME:-infisical}"
RSA_KEY_URL="${RSA_KEY_URL:-${PKG_URL}/apk/infisical.rsa.pub}"

# Colors (basic POSIX-compatible)
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo_status() {
    local status=$1
    local message=$2
    if [ "$status" = "OK" ]; then
        printf "${GREEN}[  OK  ]${NC} %s\n" "$message"
    elif [ "$status" = "FAIL" ]; then
        printf "${RED}[ FAIL ]${NC} %s\n" "$message"
    elif [ "$status" = "RUN" ]; then
        printf "[  ..  ] %s\r" "$message"
    fi
}

die() {
    echo
    printf "${RED}${BOLD}Error:${NC} %s\n" "$1"
    echo
    printf "${BOLD}For assistance, please visit:${NC}\n"
    echo "  https://github.com/Infisical/infisical"
    echo
    exit 1
}

check_tool() {
    local tool=$1
    echo_status "RUN" "Checking for required tool '$tool'..."
    if command -v "$tool" > /dev/null 2>&1; then
        echo_status "OK" "Checking for required tool '$tool'"
        return 0
    else
        echo_status "FAIL" "Checking for required tool '$tool'"
        die "$tool is not installed, but is required by this script."
    fi
}

validate_arch() {
    echo_status "RUN" "Validating system architecture..."
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            ;;
        aarch64|arm64)
            ;;
        *)
            echo_status "FAIL" "Validating system architecture"
            die "Unsupported architecture: $arch. Supported: x86_64, aarch64"
            ;;
    esac
    echo_status "OK" "Architecture supported: $arch"
}

import_rsa_key() {
    echo_status "RUN" "Importing '${PACKAGE_NAME}' repository RSA key..."
    
    # Create keys directory if it doesn't exist
    mkdir -p /etc/apk/keys
    
    # Download and install RSA public key
    if wget -q -O "/etc/apk/keys/${PACKAGE_NAME}.rsa.pub" "${RSA_KEY_URL}"; then
        chmod 644 "/etc/apk/keys/${PACKAGE_NAME}.rsa.pub"
        echo_status "OK" "Importing '${PACKAGE_NAME}' repository RSA key"
    else
        echo_status "FAIL" "Importing '${PACKAGE_NAME}' repository RSA key"
        die "Could not download RSA key from ${RSA_KEY_URL}"
    fi
}

setup_repository() {
    local repo_file="/etc/apk/repositories"
    local repo_url="${PKG_URL}/apk/stable/main/${arch}"
    
    echo_status "RUN" "Adding '${PACKAGE_NAME}' repository..."
    
    # Check if repository already exists
    if grep -q "${repo_url}" "${repo_file}" 2>/dev/null; then
        echo_status "OK" "Repository already configured"
        return 0
    fi
    
    # Add repository
    echo "${repo_url}" >> "${repo_file}"
    echo_status "OK" "Adding '${PACKAGE_NAME}' repository"
}

update_apk() {
    echo_status "RUN" "Updating Alpine repository cache..."
    if apk update > /dev/null 2>&1; then
        echo_status "OK" "Updating Alpine repository cache"
    else
        echo_status "FAIL" "Updating Alpine repository cache"
        die "Failed to update APK cache. Please check your network connection."
    fi
}

usage() {
    cat << EOF
Usage: $0 [options]

Options:
  -h, --help     Display this help message
  -r, --remove   Remove the repository configuration

Environment variables:
  PKG_URL        Base URL for packages (default: https://artifacts-cli.infisical.com)
  PACKAGE_NAME   Package name (default: infisical)

EOF
    exit 0
}

remove_repository() {
    echo "Removing ${PACKAGE_NAME} repository configuration..."
    
    # Remove from repositories file
    if [ -f /etc/apk/repositories ]; then
        sed -i "\|${PKG_URL}/apk|d" /etc/apk/repositories
        echo_status "OK" "Removed repository from /etc/apk/repositories"
    fi
    
    # Remove RSA key
    if [ -f "/etc/apk/keys/${PACKAGE_NAME}.rsa.pub" ]; then
        rm -f "/etc/apk/keys/${PACKAGE_NAME}.rsa.pub"
        echo_status "OK" "Removed RSA key"
    fi
    
    # Update cache
    apk update > /dev/null 2>&1
    
    echo
    echo "Repository removed successfully."
    exit 0
}

#
# MAIN
#

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -r|--remove)
            remove_repository
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
    shift
done

echo
echo "Executing the setup script for the '${PACKAGE_NAME}' repository..."
echo

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root (e.g., using sudo)"
fi

# Check requirements
check_tool "wget"

# Setup
detect_arch
import_rsa_key
setup_repository
update_apk

echo
printf "${GREEN}${BOLD}Success!${NC} The repository has been installed successfully.\n"
echo
echo "You can now install ${PACKAGE_NAME} with:"
echo
printf "  ${BOLD}apk add ${PACKAGE_NAME}${NC}\n"
echo
