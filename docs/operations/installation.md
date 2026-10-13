# Installation

Target platform for development: **macOS on Apple Silicon (`darwin/arm64`)**. No virtual machine or
Docker is required.

## 1. Prerequisites

```bash
# Node.js (>= 20) and npm
brew install node
# Go (>= 1.23)
brew install go
# PostgreSQL 16 and Redis
brew install postgresql@16 redis
brew services start postgresql@16
brew services start redis
```

Add PostgreSQL to your `PATH` if needed:

```bash
export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"
```

## 2. External providers

ReconNexus health-checks these tools but does not install them. Install the ones you intend to use:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
brew install amass
```

A missing provider surfaces as a `MISSING` health status in `reconnexus doctor` and
`reconnexus providers list`, and as an explicit `DEPENDENCY_MISSING` exit where a stage requires it.

## 3. ReconNexus

```bash
cd reconnexus
npm install
npm run build          # type-check + compile all TypeScript packages
```

## 4. Database

```bash
createdb reconnexus
npm run rn -- config migrate          # apply migrations (idempotent)
npm run rn -- config migrate --status # verify
```

## 5. Verify

```bash
npm run rn -- doctor
# expect: Runtime OK, postgres OK, providers listed, "doctor: healthy"
```

## 6. Go binaries (optional)

```bash
make go-build
./bin/provider-check          # provider health with exit status
```

## Production note

Local development runs everything natively. Production deployment should move workers to isolated
Linux hosts with controlled network egress and a managed PostgreSQL instance. This is documented
as future work; the local build does not require it.
