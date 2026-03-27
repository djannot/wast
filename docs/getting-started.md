# Getting Started with WAST

WAST (Web Application Security Testing) is a modern web application security testing tool designed for both AI agents and human operators. This guide will help you get started quickly.

## Quick Start for Humans

### Installation

#### From Source (Requires Go 1.21+)

```bash
# Clone the repository
git clone https://github.com/djannot/wast.git
cd wast

# Build the binary
make build

# The binary will be available at ./bin/wast
./bin/wast --version
```

#### Build for All Platforms

```bash
make build-all
```

This creates binaries for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

### First Steps

1. **Check the installation:**
   ```bash
   wast --help
   wast --version
   ```

2. **Run your first reconnaissance:**
   ```bash
   wast recon example.com
   ```

3. **Crawl a website:**
   ```bash
   wast crawl https://example.com
   ```

4. **Run a security scan (safe mode - passive checks only):**
   ```bash
   wast scan https://example.com
   ```

### Understanding Safe Mode

**WAST runs in safe mode by default** to prevent accidental active vulnerability testing against systems you don't own.

- **Safe Mode (Default)**: Only passive security checks (headers, TLS, cookies, CORS)
- **Active Mode**: Sends potentially dangerous payloads (XSS, SQLi, CSRF)

```bash
# Safe mode (default)
wast scan https://example.com

# Active testing (requires explicit permission)
wast scan https://example.com --active
```

⚠️ **WARNING**: Active testing sends attack payloads to the target. Only use `--active` on systems you own or have written permission to test. Unauthorized testing may be illegal.

### Output Formats

WAST supports multiple output formats:

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

## Quick Start for AI Agents

### MCP Server Mode

WAST includes a built-in MCP (Model Context Protocol) server for direct AI agent integration:

```bash
# Start MCP server
wast serve --mcp

# Or use the shorthand
wast --mcp
```

### MCP Integration with Claude Desktop

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

After restarting Claude Desktop, you can use natural language:

```
User: "Can you scan example.com for security issues?"
Claude: [Uses wast_scan tool with target="https://example.com"]

User: "Perform reconnaissance on test.com and include subdomains"
Claude: [Uses wast_recon tool with include_subdomains=true]
```

### Available MCP Tools

| Tool Name | Description |
|-----------|-------------|
| `wast_recon` | Reconnaissance and information gathering |
| `wast_scan` | Security vulnerability scanning (safe mode by default) |
| `wast_crawl` | Web crawling and content discovery |
| `wast_api` | API discovery and testing |
| `wast_intercept` | Traffic interception and analysis |
| `wast_headers` | Security header analysis (passive-only) |
| `wast_verify` | Verify individual security findings to reduce false positives |

### CLI Integration (Legacy)

For AI agents that don't support MCP, use structured output:

```bash
# Get reconnaissance data as JSON
wast recon example.com --output json

# The output follows a consistent structure:
# {
#   "success": true,
#   "command": "recon",
#   "message": "...",
#   "data": { ... }
# }
```

## Next Steps

- [MCP Integration Guide](mcp-integration.md) - Detailed MCP protocol documentation
- [CLI Reference](cli-reference.md) - Complete CLI command reference
- [Authentication Guide](authentication.md) - Configure authentication for testing protected apps
- [Safe Mode Guide](safe-mode.md) - Understanding safe vs active testing modes

## Common Use Cases

### Security Testing Workflow

1. **Reconnaissance** - Gather information about the target
   ```bash
   wast recon example.com --subdomains --output json
   ```

2. **Crawl** - Map the application structure
   ```bash
   wast crawl https://example.com --depth 5 --output json
   ```

3. **Scan** - Test for vulnerabilities (safe mode first)
   ```bash
   wast scan https://example.com --output sarif > results.sarif
   ```

4. **Active Testing** - With explicit permission
   ```bash
   wast scan https://example.com --active --output sarif
   ```

### API Testing Workflow

1. **Parse OpenAPI Specification**
   ```bash
   wast api --spec openapi.yaml --dry-run
   ```

2. **Test API Endpoints**
   ```bash
   wast api --spec openapi.yaml --bearer-token YOUR_TOKEN
   ```

3. **Discover APIs**
   ```bash
   wast api https://api.example.com --output json
   ```

### Authenticated Testing

Test protected applications using various authentication methods:

```bash
# Bearer token authentication
wast scan https://api.example.com --bearer-token "eyJhbGciOi..."

# Basic authentication
wast scan https://example.com/admin --basic-auth "admin:password"

# Cookie-based authentication
wast scan https://app.example.com --cookies "session=abc123" --cookies "user_id=456"

# Automated login flow
export WAST_LOGIN_PASS="password123"
wast scan https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser
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

## Support

- **GitHub Issues**: [https://github.com/djannot/wast/issues](https://github.com/djannot/wast/issues)
- **Documentation**: See the `docs/` directory for detailed guides
- **License**: MIT License (see LICENSE file)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
