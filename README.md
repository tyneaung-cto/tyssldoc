# tyssldoc

`tyssldoc` is a production-ready SSL/TLS diagnostic CLI for checking certificate health, HTTPS behavior, DNS records, and security headers from a domain name.

## Installation

### macOS/Linux (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/tyneaung-cto/tyssldoc/main/install.sh | bash
```

### Windows PowerShell (one command)

```powershell
irm https://raw.githubusercontent.com/tyneaung-cto/tyssldoc/main/install.ps1 | iex
```

### Manual download

1. Open Releases: https://github.com/tyneaung-cto/tyssldoc/releases
2. Download the archive matching your OS/architecture.
3. Extract and move `tyssldoc` (or `tyssldoc.exe`) into your PATH.

## Build from source

```bash
git clone https://github.com/tyneaung-cto/tyssldoc.git
cd tyssldoc
go mod tidy
go test ./...
go build -o tyssldoc .
```

## Usage

```bash
tyssldoc google.com
tyssldoc tech4mm.com
tyssldoc --json example.com
tyssldoc tui www.tech4mm.com
tyssldoc check example.com
tyssldoc --help
tyssldoc about
```

## Development setup

```bash
go mod tidy
go test ./...
go build -o tyssldoc .
```

## Release process

This project uses GoReleaser + GitHub Actions for automatic cross-platform releases.

### Tag and release

```bash
git tag v1.0.0
git push origin v1.0.0
```

Pushing a `v*` tag triggers `.github/workflows/release.yml` and publishes release artifacts automatically.

### Local GoReleaser test

```bash
goreleaser release --snapshot --clean
```

## Suggested `.gitignore` additions

```gitignore
# build outputs
/dist/
/tyssldoc
/tyssldoc.exe

# checksums and local artifacts
checksums.txt

# editor/OS
.DS_Store
Thumbs.db
```

## Suggested Makefile

```makefile
.PHONY: build test install release

build:
	go build -o tyssldoc .

test:
	go test ./...

install:
	go install .

release:
	goreleaser release --clean
```

## Author

- Tyne Aung
- GitHub: https://github.com/tyneaung-cto
- Project: https://github.com/tyneaung-cto/tyssldoc
