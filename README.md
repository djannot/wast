# WAST - Web Application Security Testing

WAST is a modern web application security testing tool designed for both AI agents and human operators. It provides comprehensive security testing capabilities with structured output formats for seamless automation.

## Features

- **Safe by Default**: Testing runs in safe mode by default (passive checks only), preventing accidental active testing
- **AI-First Design**: All commands support structured output formats (JSON/YAML/SARIF) for seamless AI agent integration
- **SARIF Output**: Native support for SARIF 2.1.0 format for integration with GitHub Code Scanning, VS Code, and other security tools
- **Comprehensive Testing**: Full-spectrum web security testing from reconnaissance to vulnerability scanning
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
| `wast serve --mcp` | Start MCP server for AI agent integration |

## Installation

### From Source

Requires Go 1.21 or later.

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
- Cross-Site Request Forgery (CSRF) token analysis

⚠️ **WARNING**: Active testing sends attack payloads to the target. Only use `--active` on systems you own or have written permission to test. Unauthorized testing may be illegal and could trigger security alerts.

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
- Severity mapping (high→error, medium→warning, low→note)
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
| Cross-Site Request Forgery (CSRF) | WAST-CSRF-001 | CWE-352 |
| Missing HSTS Header | WAST-HDR-001 | CWE-693 |
| Missing CSP Header | WAST-HDR-002 | CWE-693 |
| Missing X-Frame-Options | WAST-HDR-003 | CWE-693 |
| Missing X-Content-Type-Options | WAST-HDR-004 | CWE-693 |
| Insecure Cookie | WAST-COOKIE-001 | CWE-614 |
| Insecure CORS Policy | WAST-CORS-001 | CWE-942 |

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

#### Example: Running with Jaeger

```bash
# Start Jaeger all-in-one container
docker run -d --name jaeger \
  -p 4317:4317 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest

# Set telemetry endpoint
export WAST_OTEL_ENDPOINT=localhost:4317

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
│   └── commands/
│       ├── recon.go          # Reconnaissance command
│       ├── crawl.go          # Crawling command
│       ├── intercept.go      # Traffic interception command
│       ├── scan.go           # Security scanning command
│       └── api.go            # API testing command
├── pkg/
│   └── output/
│       └── formatter.go      # JSON/YAML/text output formatting
├── docs/
├── Makefile
├── go.mod
├── go.sum
├── .gitignore
└── README.md
```

## Development

### Prerequisites

- Go 1.21 or later
- Make (optional, for using Makefile)

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage
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
2. **Structured Output**: All commands support `--output json`, `--output yaml`, and `--output sarif` for machine-readable output
3. **SARIF Compliance**: Full SARIF 2.1.0 support for seamless integration with security tools and platforms
4. **Consistent Schema**: Output follows a consistent structure across all commands
5. **Exit Codes**: Meaningful exit codes for success/failure detection
6. **Quiet Mode**: `--quiet` flag for suppressing non-essential output

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

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `wast_recon` | Reconnaissance and information gathering | `target`, `timeout`, `include_subdomains` |
| `wast_scan` | Security vulnerability scanning (safe mode by default) | `target`, `timeout`, `active`, `bearer_token`, `basic_auth`, `auth_header`, `cookies` |
| `wast_crawl` | Web crawling and content discovery | `target`, `depth`, `timeout`, `respect_robots`, `bearer_token`, `basic_auth`, `auth_header`, `cookies` |
| `wast_api` | API discovery and testing | `target`, `spec_file`, `dry_run`, `timeout`, `bearer_token`, `basic_auth`, `auth_header`, `cookies` |

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

User: "Perform reconnaissance on test.com and include subdomains"
Claude: [Uses wast_recon tool with include_subdomains=true]

User: "Scan api.example.com with bearer token authentication"
Claude: [Uses wast_scan tool with bearer_token="your-token-here"]
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

// Multiple authentication methods (combined)
{
  "target": "https://api.example.com",
  "bearer_token": "token123",
  "cookies": ["session=xyz789"]
}

// Automated login flow (form-based)
{
  "target": "https://app.example.com/dashboard",
  "login_url": "https://app.example.com/login",
  "login_user": "testuser",
  "login_pass": "password123"
}

// Automated login with custom field names
{
  "target": "https://app.example.com/admin",
  "login_url": "https://app.example.com/auth/login",
  "login_user": "admin@example.com",
  "login_pass": "secretpass",
  "login_user_field": "email",
  "login_pass_field": "pwd"
}
```

**Automated Login Flow:**

WAST supports automated login flows for testing session-based web applications. Instead of manually extracting cookies, WAST can authenticate by submitting credentials to a login endpoint and automatically capturing session cookies.

This feature is useful for:
- Testing authenticated areas of web applications
- AI agents testing real-world applications autonomously
- Automated security testing in CI/CD pipelines

**CLI Examples:**

```bash
# Basic login flow (form-based authentication)
# Recommended: Use environment variable for password
export WAST_LOGIN_PASS="password123"
wast crawl https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser

# Alternative: Pass password directly (NOT RECOMMENDED - exposes in shell history)
wast crawl https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser \
  --login-pass password123

# Login with custom field names
export WAST_LOGIN_PASS="secretpass"
wast scan https://app.example.com/admin \
  --login-url https://app.example.com/auth/login \
  --login-user admin@example.com \
  --login-user-field email \
  --login-pass-field pwd

# API testing with login flow
export WAST_LOGIN_PASS="apipass"
wast api https://api.example.com \
  --login-url https://api.example.com/auth/login \
  --login-user apiuser
```

**How it works:**
1. WAST submits credentials to the specified login endpoint via POST request
2. The server responds with session cookies (and potentially redirects)
3. WAST captures these cookies automatically
4. Subsequent requests include the captured session cookies
5. WAST detects login failures (wrong status codes, error messages in response)

**Supported login types:**
- Form-based authentication (default, Content-Type: application/x-www-form-urlencoded)
- JSON API authentication (Content-Type: application/json)
- Redirects after successful login (302/303 status codes)

**Security Best Practices:**

⚠️ **IMPORTANT:** Passing credentials via command-line flags exposes them in shell history and process listings. Follow these security best practices:

**Recommended: Use Environment Variables**
```bash
# Set password via environment variable to avoid shell history exposure
export WAST_LOGIN_PASS="your_password_here"

# Run WAST without exposing password in command line
wast crawl https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser

# Clear the environment variable when done
unset WAST_LOGIN_PASS
```

**Alternative: Use MCP Protocol with Secure Credential Management**
- When using MCP (Model Context Protocol), credentials are passed as parameters
- MCP parameters may be logged by clients/servers
- Consider implementing secure credential storage in your MCP client

**Additional Security Considerations:**
- Only use automated login for testing/development environments
- Never hardcode credentials in scripts or configuration files
- Use unique test accounts with minimal privileges
- Rotate credentials regularly
- Monitor for unauthorized access attempts

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
