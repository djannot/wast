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
| `wast_scan` | Security vulnerability scanning (safe mode by default) | `target`, `timeout`, `active` |
| `wast_crawl` | Web crawling and content discovery | `target`, `depth`, `timeout`, `respect_robots` |
| `wast_api` | API discovery and testing | `target`, `spec_file`, `dry_run`, `timeout` |

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
```

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
