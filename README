<h1 align="center">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-white.svg#gh-dark-mode-only" alt="infisical">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-black.svg#gh-light-mode-only" alt="infisical">
</h1>
<p align="center">
  <p align="center"><b>The official Infisical CLI</b>: Inject secrets into applications and manage your Infisical infrastructure.</p>
</p>

<h4 align="center">
  <a href="https://infisical.com/slack">Slack</a> |
  <a href="https://infisical.com/">Infisical Cloud</a> |
  <a href="https://infisical.com/docs/cli/overview">CLI Docs</a> |
  <a href="https://www.infisical.com">Website</a>
</h4>

<h4 align="center">
  <a href="https://github.com/Infisical/cli/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Infisical CLI is released under the MIT license." />
  </a>
  <a href="https://github.com/infisical/cli/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://github.com/Infisical/cli/issues">
    <img src="https://img.shields.io/github/commit-activity/m/infisical/cli" alt="git commit activity" />
  </a>
  <a href="https://infisical.com/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
  <a href="https://twitter.com/infisical">
    <img src="https://img.shields.io/twitter/follow/infisical?label=Follow" alt="Infisical Twitter" />
  </a>
</h4>

## Introduction

The **[Infisical CLI](https://infisical.com/docs/cli/overview)** is a powerful command-line tool for secret management that allows you to:

- **Inject secrets** into applications and development workflows
- **Scan for secret leaks** in your codebase and git history
- **Export secrets** to various formats (dotenv, JSON, YAML)
- **Authenticate** with Infisical Cloud or self-hosted instances
- **Integrate** with CI/CD pipelines and Docker containers

## Installation

Choose your preferred installation method:

### Package Managers

**macOS:** `brew install infisical/get-cli/infisical`

**Windows:** `scoop install infisical` or `winget install infisical`

**NPM:** `npm install -g @infisical/cli`

**Linux:**

- **Ubuntu/Debian:** `curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | sudo -E bash && sudo apt-get install -y infisical`
- **Alpine:** `curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.alpine.sh' | bash && sudo apk add infisical`
- **RHEL/CentOS:** `curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.rpm.sh' | sudo -E bash && sudo yum install infisical`
- **Arch:** `yay -S infisical-bin`

### Direct Download

Download binaries from [GitHub Releases](https://github.com/Infisical/cli/releases).

## Quick Start

### Local Development

```bash
# Login and initialize
infisical login
infisical init

# Inject secrets into your app
infisical run --env=dev -- npm start
infisical run --env=production -- python app.py
```

### CI/CD & Production

```bash
# Authenticate with machine identity
export INFISICAL_TOKEN=$(infisical login --method=universal-auth --client-id=<id> --client-secret=<secret> --silent --plain)

# Export secrets to file
infisical export --format=dotenv-export > .env
```

## Key Features

### 🔐 Secret Injection

```bash
infisical run --env=production -- npm start
```

### 🔍 Secret Scanning

```bash
infisical scan --verbose
infisical scan install --pre-commit-hook
```

### 🗂️ Secret Management

```bash
infisical export --env=dev --format=dotenv
infisical secrets get API_KEY
```

### 🚀 CI/CD Integration

```bash
infisical run --token=$INFISICAL_TOKEN -- pytest
```

### 🏢 Self-Hosted Support

```bash
infisical login  # Choose your instance
export INFISICAL_API_URL="https://your-instance.com/api"
```

## Documentation

- **[CLI Overview](https://infisical.com/docs/cli/overview)** - Complete installation and setup guide
- **[Usage Guide](https://infisical.com/docs/cli/usage)** - Detailed usage scenarios
- **[Commands Reference](https://infisical.com/docs/cli/commands)** - All available commands
- **[FAQ](https://infisical.com/docs/cli/faq)** - Common questions and troubleshooting

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/Infisical/cli.git
cd cli
go build -o infisical .
go test ./...
```

## Support

- **[Documentation](https://infisical.com/docs/cli/overview)** - Complete guides and reference
- **[Slack Community](https://infisical.com/slack)** - Get help from the community
- **[GitHub Issues](https://github.com/Infisical/cli/issues)** - Report bugs and request features

## License

The Infisical CLI is available under the [MIT License](LICENSE).

## Security

Please do not file GitHub issues for security vulnerabilities. Instead, contact us at security@infisical.com.

---

<p align="center">
  Made with ❤️ by the <a href="https://infisical.com">Infisical</a> team
</p>
