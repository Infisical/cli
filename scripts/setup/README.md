# Repository Setup Scripts

This folder contains setup scripts that end-users run to configure their systems to install the Infisical CLI from our package repositories.

## Scripts

| Script | Target System | Description |
|--------|---------------|-------------|
| `setup.deb.sh` | Debian/Ubuntu | Configures APT repository for `.deb` packages |
| `setup.rpm.sh` | RHEL/Fedora/CentOS/SUSE | Configures YUM/DNF/Zypper repository for `.rpm` packages |
| `setup.apk.sh` | Alpine Linux | Configures APK repository for `.apk` packages |

## How They're Used

These scripts are hosted on our S3 artifacts bucket and users download and run them to set up the repository:

```bash
# Debian/Ubuntu
curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | sudo bash

# RHEL/Fedora/CentOS
curl -1sLf 'https://artifacts-cli.infisical.com/setup.rpm.sh' | sudo bash

# Alpine Linux
wget -qO- 'https://artifacts-cli.infisical.com/setup.apk.sh' | sudo sh
```

After running the setup script, users can install the CLI using their native package manager:

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install infisical

# RHEL/Fedora
sudo yum install infisical  # or dnf/zypper

# Alpine
sudo apk add infisical
```

## What Each Script Does

1. **Imports GPG/RSA signing keys** - Downloads and installs the public key used to verify package signatures
2. **Configures the repository** - Adds the Infisical repository to the system's package manager
3. **Updates package cache** - Refreshes the package list so the CLI can be installed

## Deployment

These scripts are uploaded to S3 during the release process. They are served from:
- `https://artifacts-cli.infisical.com/setup.deb.sh`
- `https://artifacts-cli.infisical.com/setup.rpm.sh`
- `https://artifacts-cli.infisical.com/setup.apk.sh`
