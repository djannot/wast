# WAST - Web & AI Security Testing

WAST is a modern security testing tool designed for both AI agents and human operators. It provides comprehensive web application security testing and MCP (Model Context Protocol) server security scanning, with structured output formats for seamless automation.

## Features

- **Safe by Default**: Testing runs in safe mode by default (passive checks only), preventing accidental active testing
- **AI-First Design**: All commands support structured output formats (JSON/YAML/SARIF) for seamless AI agent integration
- **MCP Server Security Scanning**: Discover and scan MCP servers for vulnerabilities — prompt injection, tool injection, excessive permissions, auth bypass
- **SARIF Output**: Native support for SARIF 2.1.0 format for integration with GitHub Code Scanning, VS Code, and other security tools
- **Comprehensive Web Testing**: Full-spectrum web security testing from reconnaissance to vulnerability scanning
- **Cross-Platform**: Single binary distribution for Linux, macOS, and Windows
- **Modular Architecture**: Command-based structure for targeted testing

### Commands

| Command | Description |
|---------|-------------|
| `wast recon` | Reconnaissance and information gathering |
| `wast crawl` | Web crawling and content discovery |
| `wast intercept` | Traffic interception and analysis |
| `wast scan` | Security vulnerability scanning |
| `wast api` | API security testing |
| `wast mcpscan` | MCP server discovery and security scanning |
| `wast serve --mcp` | Start MCP server for AI agent integration |

## Installation

### From Source

Requires Go 1.26 or later.

```bash
# Clone the repository
git clone https://github.com/djannot/wast.git
cd wast

# Build the binary
make build

# The binary will be available at ./bin/wast
```

### Build for All Platforms

```bash
make build-all
```

This creates binaries for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

## Usage

### Basic Usage

```bash
# Show help
wast --help

# Show version
wast --version

# Run reconnaissance
wast recon example.com

# Crawl a website
wast crawl https://example.com

# Run a security scan (safe mode - passive checks only)
wast scan https://example.com

# Run active vulnerability testing (requires explicit permission)
wast scan https://example.com --active

# Discover and scan with crawling (finds forms, endpoints, then scans them)
wast scan https://example.com --active --discover --depth 3
```

### Safe Mode

**WAST runs in safe mode by default** to prevent accidental active vulnerability testing against systems you don't own or have permission to test.

#### Safe Mode (Default)
In safe mode, only **passive security checks** are performed:
- HTTP security headers analysis
- SSL/TLS configuration review
- Cookie security attributes
- CORS policy validation

```bash
# Safe mode is the default - only passive checks
wast scan https://example.com
wast scan https://example.com --safe-mode=true
```

#### Active Testing Mode
Active testing mode sends **potentially dangerous payloads** to the target and should only be used on systems you own or have explicit permission to test:

```bash
# Enable active vulnerability testing
wast scan https://example.com --active

# Or explicitly disable safe mode
wast scan https://example.com --safe-mode=false
```

**Active testing includes:**
- Cross-Site Scripting (XSS) payload injection
- SQL Injection (SQLi) testing with various payloads
- NoSQL Injection (NoSQLi) testing
- Command Injection (CMDi) testing
- Cross-Site Request Forgery (CSRF) token analysis
- Server-Side Request Forgery (SSRF) testing
- Open Redirect detection
- Path Traversal / Local File Inclusion (LFI) testing
- Server-Side Template Injection (SSTI) testing
- XML External Entity (XXE) injection testing

#### Discovery Mode

Discovery mode crawls the target to find forms and endpoints, then scans all discovered attack surfaces with their actual field names:

```bash
# All-in-one: crawl and scan in one step
wast scan https://example.com --active --discover

# Control crawl depth (default: 2)
wast scan https://example.com --active --discover --depth 3

# Authenticated discovery scan
wast scan https://example.com --active --discover \
  --cookie "session=abc123" --cookie "security=low"
```

#### Two-Step Workflow with Targets File

For more control, separate crawling from scanning. Review crawl results before scanning:

```bash
# Step 1: Crawl and save results
wast crawl https://example.com --output json > targets.json

# Step 2: Review targets.json, then scan
wast scan --targets targets.json --active
```

The `--targets` flag accepts JSON output from `wast crawl`. This enables incremental workflows, manual curation of targets, and CI pipelines with approval gates between discovery and scanning.

#### Open Redirect Canary Domain

Open redirect detection works by injecting a canary domain into redirect payloads and checking whether the application redirects to that domain. By default, WAST uses `example.com` (an RFC 2606-reserved domain) as the canary.

To eliminate false positives and confirm real redirect vulnerabilities, use a domain you control:

```bash
# Use a custom canary domain you own
wast scan https://example.com --active --redirect-canary-domain redirect-canary.yourdomain.com
```

With a domain you control you can also verify findings independently by monitoring DNS or HTTP requests to that domain during the scan.

> **Note**: The `--redirect-canary-domain` flag is only meaningful when active testing is enabled (`--active`).

### MCP Server Security Scanning

WAST can discover and scan MCP (Model Context Protocol) servers for security vulnerabilities. MCP servers expose tools via JSON-RPC 2.0 — these tools are a new attack surface that traditional web scanners don't cover.

#### Discovery

Find MCP servers locally, on a specific host, or across an entire domain:

```bash
# Discover all MCP servers configured on your machine
wast mcpscan discover

# Scan a project directory for MCP dependencies
wast mcpscan discover --project-dir /path/to/project

# Probe a specific host for MCP endpoints
wast mcpscan discover --network example.com

# Deep discovery: enumerate subdomains via CT logs and DNS,
# then probe each discovered subdomain for MCP endpoints
wast mcpscan discover --network example.com --deep
```

**Local discovery** checks:
- Claude Desktop config (`claude_desktop_config.json`)
- Claude Code config (`.claude.json`, `.mcp.json`)
- Cursor config (`~/.cursor/mcp.json`)
- VS Code / Copilot config (`.vscode/mcp.json`)
- Cline and Windsurf configs
- NPM/PyPI dependencies for known MCP server packages

**Network discovery** (`--network`) probes a host for MCP endpoints at common paths (`/.well-known/mcp`, `/mcp`, `/api/mcp`, `/v1/mcp`, `/sse`). Detects both open and auth-protected (401) endpoints. Accepts bare domains (`example.com`) or full URLs (`https://example.com`).

**Deep discovery** (`--network` + `--deep`) first enumerates subdomains using Certificate Transparency logs and DNS zone transfers, then probes every discovered subdomain for MCP endpoints. This can uncover MCP servers that aren't publicly documented.

#### Scanning a Single Server

Scan a specific MCP server for vulnerabilities:

```bash
# Scan a stdio-based MCP server (passive checks only)
wast mcpscan stdio -- npx @modelcontextprotocol/server-filesystem /tmp

# Scan an SSE-based MCP server
wast mcpscan sse https://example.com/sse

# Scan an HTTP-based MCP server
wast mcpscan http https://example.com/mcp

# Enable active checks (sends payloads to tool parameters)
wast mcpscan stdio --active -- node my-server.js
```

#### Scanning Multiple Servers

Discover and scan all MCP servers in one step, or use a two-step workflow:

```bash
# All-in-one: discover locally configured servers, then scan them
wast mcpscan scan --discover --active

# All-in-one: discover across subdomains, then scan
wast mcpscan scan --discover --network example.com --deep --active

# Two-step: discover first, review, then scan
wast mcpscan discover --network example.com --deep --output json > mcp-targets.json
# ... review mcp-targets.json ...
wast mcpscan scan --targets mcp-targets.json --active
```

**Passive checks (safe mode):**
- **Schema analysis** — Enumerate tools, flag missing input validation, overly permissive parameters
- **Prompt injection detection** — Analyze tool descriptions for hidden AI-directed instructions, Unicode tricks, encoded payloads
- **Permission auditing** — Flag dangerous capabilities (file system access, shell execution, network requests)
- **Tool shadowing** — Detect name collisions and typosquatting across multiple servers

**Active checks (requires `--active`):**
- **Tool parameter injection** — Send SQLi, CMDi, path traversal payloads through tool parameters
- **Data exposure** — Invoke tools and scan responses for leaked credentials, PII, internal paths
- **SSRF via tools** — Test URL-accepting parameters for server-side request forgery
- **Auth bypass** — Test unauthenticated access and per-tool authorization

### Output Formats

WAST supports multiple output formats for different use cases:

```bash
# Human-readable text (default)
wast scan https://example.com

# JSON output (ideal for AI agents and automation)
wast scan https://example.com --output json

# YAML output
wast scan https://example.com --output yaml

# SARIF 2.1.0 output (for security tool integration)
wast scan https://example.com --output sarif
```

#### SARIF Output Format

SARIF (Static Analysis Results Interchange Format) is the industry-standard format for security tool output. WAST implements SARIF 2.1.0 with full support for:

- **GitHub Code Scanning**: Upload results directly to GitHub Advanced Security
- **IDE Integration**: View findings in VS Code SARIF Viewer and other IDEs
- **CI/CD Pipelines**: Standard format supported by most security pipelines
- **Cross-Tool Interoperability**: Compatible with any SARIF-consuming tool

**SARIF Output Features:**
- Complete rule definitions with CWE references
- Severity mapping (high->error, medium->warning, low->note)
- Location information with URIs
- Markdown-formatted remediation guidance
- Full compliance with SARIF 2.1.0 specification

**Example Usage:**

```bash
# Save scan results to file
wast scan https://example.com --output sarif > results.sarif

# Direct upload to GitHub Code Scanning (requires gh CLI)
wast scan https://example.com --output sarif | gh code-scanning upload

# View in VS Code with SARIF Viewer extension
wast scan https://example.com --output sarif > scan.sarif && code scan.sarif
```

**Rule IDs and CWE Mappings:**

| Vulnerability Type | Rule ID | CWE Reference |
|-------------------|---------|---------------|
| Cross-Site Scripting (XSS) | WAST-XSS-001 | CWE-79 |
| SQL Injection | WAST-SQLI-001 | CWE-89 |
| NoSQL Injection | WAST-NOSQLI-001 | CWE-943 |
| Command Injection (CMDi) | WAST-CMDI-001 | CWE-78 |
| Cross-Site Request Forgery (CSRF) | WAST-CSRF-001 | CWE-352 |
| Server-Side Request Forgery (SSRF) | WAST-SSRF-001 | CWE-918 |
| Open Redirect | WAST-REDIRECT-001 | CWE-601 |
| Path Traversal / LFI | WAST-LFI-001 | CWE-22 |
| Server-Side Template Injection (SSTI) | WAST-SSTI-001 | CWE-94 |
| XML External Entity (XXE) | WAST-XXE-001 | CWE-611 |
| Missing HSTS Header | WAST-HDR-001 | CWE-693 |
| Missing CSP Header | WAST-HDR-002 | CWE-693 |
| Missing X-Frame-Options | WAST-HDR-003 | CWE-693 |
| Missing X-Content-Type-Options | WAST-HDR-004 | CWE-693 |
| Insecure Cookie | WAST-COOKIE-001 | CWE-614 |
| Insecure CORS Policy | WAST-CORS-001 | CWE-942 |
| Insecure WebSocket Protocol | WAST-WS-001 | CWE-319 |
| Missing WebSocket Origin Validation | WAST-WS-002 | CWE-346 |

### Verbosity Control

```bash
# Quiet mode - suppress all output except errors
wast scan https://example.com --quiet

# Verbose mode - detailed output
wast scan https://example.com --verbose
```

### OpenTelemetry Tracing

WAST supports OpenTelemetry (OTEL) tracing for comprehensive observability of scan operations. This enables you to monitor scan progress, identify performance bottlenecks, and correlate scan timing with findings.

#### Configuration

Telemetry is completely opt-in and has zero overhead when disabled. You can enable it in two ways:

1. **Environment Variable** (recommended for automation):
```bash
export WAST_OTEL_ENDPOINT=localhost:4317
wast --mcp
```

2. **CLI Flag**:
```bash
wast --mcp --telemetry-endpoint localhost:4317
```

#### Optional Configuration

You can customize the service name (default: "wast"):
```bash
export WAST_OTEL_SERVICE_NAME=my-wast-instance
export WAST_OTEL_ENDPOINT=localhost:4317
wast --mcp
```

**Security Note**: By default, WAST uses TLS encryption for telemetry data transmission. For local development with tools like Jaeger, you can disable TLS by setting:
```bash
export WAST_OTEL_INSECURE=true
```

#### Example: Running with Jaeger

```bash
# Start Jaeger all-in-one container
docker run -d --name jaeger \
  -p 4317:4317 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest

# Set telemetry endpoint (insecure mode for local development)
export WAST_OTEL_ENDPOINT=localhost:4317
export WAST_OTEL_INSECURE=true

# Run WAST in MCP mode with telemetry
wast --mcp

# Open Jaeger UI at http://localhost:16686
```

#### Span Structure

WAST emits spans for all major operations:

```
wast.scan
├── wast.recon
│   ├── wast.dns.enumerate
│   └── wast.tls.analyze
├── wast.scanner.headers
├── wast.scanner.xss
│   └── wast.http.request (per payload)
├── wast.scanner.sqli
├── wast.scanner.csrf
└── wast.scanner.ssrf
```

#### Compatible Backends

WAST uses the OTLP gRPC protocol and works with any compatible backend:
- Jaeger
- Zipkin
- Honeycomb
- Grafana Tempo
- DataDog APM
- New Relic
- Any OTLP-compatible collector

## Project Structure

```
wast/
├── cmd/
│   └── wast/
│       ├── main.go           # Entry point
│       └── root.go           # Root command definition
├── internal/
│   ├── commands/             # CLI command implementations
│   │   ├── recon.go          # Reconnaissance command
│   │   ├── crawl.go          # Crawling command
│   │   ├── intercept.go      # Traffic interception command
│   │   ├── scan.go           # Security scanning command
│   │   ├── api.go            # API testing command
│   │   ├── mcpscan.go        # MCP server security scanning command
│   │   └── serve.go          # MCP server command
│   └── mcp/                  # MCP protocol implementation
│       └── server.go         # MCP server and tools
├── pkg/                      # Public packages
│   ├── auth/                 # Authentication configuration
│   ├── crawler/              # Web crawling functionality
│   ├── dns/                  # DNS enumeration
│   ├── scanner/              # Web vulnerability scanning
│   ├── mcpscan/              # MCP server security scanning
│   │   ├── client.go         # MCP client (stdio/SSE/HTTP transports)
│   │   ├── scanner.go        # Scan orchestrator
│   │   ├── discovery.go      # MCP server discovery
│   │   └── checks/           # Security checks
│   │       ├── schema.go     # Schema analysis
│   │       ├── prompt.go     # Prompt injection detection
│   │       ├── permissions.go # Permission auditing
│   │       ├── shadowing.go  # Tool name collision detection
│   │       ├── injection.go  # Parameter injection testing
│   │       ├── exposure.go   # Data exposure analysis
│   │       ├── ssrf.go       # SSRF via tool parameters
│   │       └── auth.go       # Auth bypass testing
│   ├── api/                  # API testing
│   ├── proxy/                # Traffic interception proxy
│   ├── tls/                  # TLS analysis
│   ├── output/               # Output formatting (JSON/YAML/SARIF)
│   └── ratelimit/            # Rate limiting
├── test/
│   └── integration/          # Integration tests
│       ├── dvwa_test.go      # DVWA benchmark tests
│       ├── juiceshop/        # Juice Shop benchmark tests
│       ├── webgoat/          # WebGoat benchmark tests
│       └── mcpscan/          # MCP scan integration tests
├── docs/                     # Comprehensive documentation
│   ├── getting-started.md    # Quick start guide for humans and AI agents
│   ├── mcp-integration.md    # MCP protocol documentation with examples
│   ├── cli-reference.md      # Complete CLI command reference
│   ├── authentication.md     # Authentication methods guide
│   └── safe-mode.md          # Safe vs active mode explanation
├── docker-compose.test.yml   # DVWA integration test environment
├── Makefile
├── go.mod
├── go.sum
├── .gitignore
├── LICENSE
└── README.md
```

## Development

### Prerequisites

- Go 1.26 or later
- Make (optional, for using Makefile)
- Docker (for integration tests)

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all
```

### Testing

```bash
# Run all unit tests
make test

# Run tests with coverage report
make test-coverage

# Run coverage check (enforced minimum threshold)
make coverage-check

# Run DVWA integration tests (requires Docker)
make test-dvwa

# Run MCP scan integration tests
make test-mcpscan
```

### Linting

```bash
# Run linters
make lint

# Format code
make fmt

# Check formatting
make fmt-check
```

### Dependencies

```bash
# Download and tidy dependencies
make deps
```

## AI Agent Integration

WAST is designed with first-class support for AI agent integration. Key features:

1. **MCP Server Mode**: Native Model Context Protocol (MCP) server for direct AI agent integration
2. **MCP Security Scanning**: Scan other MCP servers for vulnerabilities via `wast_mcpscan` tool
3. **Structured Output**: All commands support `--output json`, `--output yaml`, and `--output sarif` for machine-readable output
4. **SARIF Compliance**: Full SARIF 2.1.0 support for seamless integration with security tools and platforms
5. **Consistent Schema**: Output follows a consistent structure across all commands
6. **Exit Codes**: Meaningful exit codes for success/failure detection
7. **Quiet Mode**: `--quiet` flag for suppressing non-essential output

### MCP Server Mode

WAST includes a built-in MCP (Model Context Protocol) server that exposes security testing capabilities as standardized tools for AI assistants like Claude.

**Starting the MCP Server:**

```bash
# Start MCP server
wast serve --mcp

# Or use the shorthand flag on the root command
wast --mcp
```

**Available MCP Tools:**

| Tool Name | Description | Key Parameters |
|-----------|-------------|----------------|
| `wast_recon` | Reconnaissance and information gathering | `target`, `timeout`, `include_subdomains` |
| `wast_scan` | Security vulnerability scanning (safe mode by default) | `target`, `active`, `discover`, `depth`, `scanners`, `cookies` |
| `wast_crawl` | Web crawling and content discovery | `target`, `depth`, `timeout`, `cookies` |
| `wast_api` | API discovery and testing | `target`, `spec_file`, `dry_run` |
| `wast_headers` | Passive-only security header analysis | `target`, `timeout` |
| `wast_intercept` | Intercept and analyze HTTP/HTTPS traffic | `port`, `duration`, `save_file` |
| `wast_verify` | Verify individual findings to reduce false positives | `finding_type`, `finding_url`, `parameter`, `payload` |
| `wast_websocket` | WebSocket security scanning | `target`, `active`, `timeout` |
| `wast_mcpscan` | MCP server discovery and security scanning | `mode`, `transport`, `target`, `active`, `network`, `deep` |

**MCP Integration Example (Claude Desktop):**

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "wast": {
      "command": "/path/to/wast",
      "args": ["--mcp"]
    }
  }
}
```

After restarting Claude Desktop, you can use natural language to invoke WAST tools:

```
User: "Can you scan example.com for security issues?"
Claude: [Uses wast_scan tool with target="https://example.com"]

User: "Scan example.com actively and discover all forms"
Claude: [Uses wast_scan tool with active=true, discover=true, depth=3]

User: "Discover all MCP servers on my machine"
Claude: [Uses wast_mcpscan tool with mode="discover"]

User: "Find all MCP servers across example.com subdomains"
Claude: [Uses wast_mcpscan tool with mode="discover", network="example.com", deep=true]

User: "Scan the filesystem MCP server for vulnerabilities"
Claude: [Uses wast_mcpscan tool with transport="stdio", target="npx", args=["@modelcontextprotocol/server-filesystem", "/tmp"]]
```

**Authentication Parameters:**

All MCP tools that perform HTTP requests (`wast_scan`, `wast_crawl`, `wast_api`) support authentication parameters for testing protected endpoints:

- `bearer_token` (string): Bearer token for Authorization header
- `basic_auth` (string): Basic auth credentials in format 'user:pass'
- `auth_header` (string): Custom auth header in format 'HeaderName: Value'
- `cookies` (array of strings): Cookies to include in requests (format: 'name=value')
- `login_url` (string): Login endpoint URL for automated authentication
- `login_user` (string): Username for automated login
- `login_pass` (string): Password for automated login
- `login_user_field` (string): Form field name for username (default: 'username')
- `login_pass_field` (string): Form field name for password (default: 'password')
- `login_token_field` (string): Dot-separated JSON path to extract a bearer token from login response body

**Authentication Examples:**

```javascript
// Bearer token authentication
{
  "target": "https://api.example.com",
  "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

// Basic authentication
{
  "target": "https://example.com/admin",
  "basic_auth": "admin:secretpassword"
}

// Custom header authentication
{
  "target": "https://api.example.com",
  "auth_header": "X-API-Key: abc123xyz789"
}

// Cookie-based authentication
{
  "target": "https://app.example.com",
  "cookies": ["session=abc123", "user_id=456"]
}

// Automated login flow (form-based)
{
  "target": "https://app.example.com/dashboard",
  "login_url": "https://app.example.com/login",
  "login_user": "testuser",
  "login_pass": "password123"
}

// JWT-based login (extract token from response body)
{
  "target": "https://api.example.com",
  "login_url": "https://api.example.com/rest/user/login",
  "login_user": "admin@example.com",
  "login_pass": "admin123",
  "login_content_type": "json",
  "login_token_field": "authentication.token"
}
```

**Automated Login Flow:**

WAST supports automated login flows for testing session-based web applications. Instead of manually extracting cookies, WAST can authenticate by submitting credentials to a login endpoint and automatically capturing session cookies or JWT tokens.

**CLI Examples:**

```bash
# Basic login flow (form-based authentication)
export WAST_LOGIN_PASS="password123"
wast crawl https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser

# Login with custom field names
export WAST_LOGIN_PASS="secretpass"
wast scan https://app.example.com/admin \
  --login-url https://app.example.com/auth/login \
  --login-user admin@example.com \
  --login-user-field email \
  --login-pass-field pwd

# JWT-based login (e.g., OWASP Juice Shop)
export WAST_LOGIN_PASS="admin123"
wast scan https://juice-shop.example.com \
  --login-url https://juice-shop.example.com/rest/user/login \
  --login-user admin@juice-sh.op \
  --login-content-type json \
  --login-token-field authentication.token
```

**Security Best Practices:**

- Set password via `WAST_LOGIN_PASS` environment variable to avoid shell history exposure
- Use unique test accounts with minimal privileges
- Only use automated login for testing/development environments
- When using MCP, be aware that credentials in parameters may be logged by clients/servers

**MCP Protocol Details:**
- Protocol: JSON-RPC 2.0 over stdio
- Specification: [MCP Specification](https://spec.modelcontextprotocol.io/)
- Safe by default: All tools respect WAST's safe mode defaults (e.g., scan tool defaults to `active=false`)

### CLI Integration (Legacy)

For AI agents that don't support MCP, WAST can still be used via CLI with structured output:

```bash
# Get reconnaissance data as JSON
wast recon example.com --output json

# Parse the output in your AI agent
# The output will be structured like:
# {
#   "success": true,
#   "command": "recon",
#   "message": "...",
#   "data": { ... }
# }
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
