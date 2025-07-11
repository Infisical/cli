<div align="center">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-white.svg#gh-dark-mode-only" alt="infisical">
  <img width="300" src="https://raw.githubusercontent.com/Infisical/infisical/main/img/logoname-black.svg#gh-light-mode-only" alt="infisical">
</div>

<p align="center">
  <b>The official Infisical CLI</b>: Inject secrets into applications and manage your Infisical infrastructure.
</p>

## Introduction

The **[Infisical CLI](https://infisical.com/docs/cli/overview)** is a powerful command-line tool for secret management that allows you to:

- **Inject secrets** into applications and development workflows
- **Scan for secret leaks** in your codebase and git history
- **Export secrets** to various formats (dotenv, JSON, YAML)
- **Authenticate** with Infisical Cloud or self-hosted instances
- **Integrate** with CI/CD pipelines and Docker containers

## Installation

### Package Managers

**macOS**

```bash
brew install infisical/get-cli/infisical
```

**Windows**

```bash
# Scoop
scoop install infisical

# Winget
winget install infisical
```

**NPM**

```bash
npm install -g @infisical/cli
```

**Linux**

_Ubuntu/Debian:_

```bash
curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | sudo -E bash
sudo apt-get install -y infisical
```

_Alpine:_

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.alpine.sh' | bash
sudo apk add infisical
```

_RHEL/CentOS:_

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.rpm.sh' | sudo -E bash
sudo yum install infisical
```

_Arch Linux:_

```bash
yay -S infisical-bin
```

### Direct Download

Download binaries from [GitHub Releases](https://github.com/Infisical/cli/releases).

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
