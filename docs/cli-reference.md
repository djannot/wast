# CLI Reference

Complete command-line interface reference for WAST.

## Global Flags

These flags are available for all commands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output` | string | text | Output format: text, json, yaml, sarif |
| `--quiet` | boolean | false | Suppress all output except errors |
| `--verbose` | boolean | false | Enable verbose output |
| `--version` | boolean | false | Show version information |
| `--help` | boolean | false | Show help information |
| `--mcp` | boolean | false | Start MCP server mode |
| `--telemetry-endpoint` | string | - | OpenTelemetry collector endpoint (e.g., localhost:4317) |

### Authentication Flags (Available for scan, crawl, api)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--bearer-token` | string | - | Bearer token for Authorization header |
| `--basic-auth` | string | - | Basic auth credentials in format 'user:pass' |
| `--auth-header` | string | - | Custom auth header in format 'HeaderName: Value' |
| `--cookies` | string[] | - | Cookies to include (format: 'name=value'). Can be specified multiple times |
| `--login-url` | string | - | Login endpoint URL for automated authentication |
| `--login-user` | string | - | Username for automated login |
| `--login-pass` | string | - | Password for automated login (use WAST_LOGIN_PASS env var instead) |
| `--login-user-field` | string | username | Form field name for username |
| `--login-pass-field` | string | password | Form field name for password |

### Rate Limiting Flags (Available for scan, crawl, api)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rate-limit` | float | 0 | Maximum requests per second (0 for unlimited) |
| `--delay` | integer | 0 | Delay between requests in milliseconds |

## Commands

### wast recon

Perform reconnaissance and information gathering on a target domain.

#### Usage

```bash
wast recon [target] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--timeout` | duration | 10s | Timeout for DNS queries (e.g., '10s', '1m') |
| `--subdomains` | boolean | false | Enable subdomain discovery via CT logs and zone transfer |

#### Examples

```bash
# Basic reconnaissance
wast recon example.com

# With subdomain discovery
wast recon example.com --subdomains

# JSON output with longer timeout
wast recon example.com --output json --timeout 30s

# Show available methods (no target)
wast recon
```

#### Output Structure

```json
{
  "success": true,
  "command": "recon",
  "message": "Reconnaissance completed",
  "data": {
    "target": "example.com",
    "dns": {
      "a_records": ["93.184.216.34"],
      "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
      "mx_records": ["mail.example.com"],
      "ns_records": ["ns1.example.com", "ns2.example.com"],
      "txt_records": ["v=spf1 ..."],
      "subdomains": ["www.example.com", "api.example.com"]
    },
    "tls": {
      "version": "TLS 1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "certificate": {
        "subject": "CN=example.com",
        "issuer": "Let's Encrypt",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": "2024-04-01T00:00:00Z",
        "san": ["example.com", "www.example.com"]
      }
    }
  }
}
```

---

### wast scan

Security vulnerability scanning with safe mode by default.

#### Usage

```bash
wast scan [target] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--timeout` | integer | 30 | HTTP request timeout in seconds |
| `--safe-mode` | boolean | true | Run in safe mode (passive checks only) |
| `--active` | boolean | false | Enable active vulnerability testing (same as --safe-mode=false) |
| `--verify` | boolean | false | Enable finding verification (requires --active) |
| `--discover` | boolean | false | Crawl first to discover forms/endpoints, then scan |
| `--depth` | integer | 2 | Maximum crawl depth for discovery mode |
| `--concurrency` | integer | 5 | Concurrent workers for crawl phase (with --discover) |
| `--scan-concurrency` | integer | 5 | Concurrent workers for scanning (with --discover) |

Plus: [Authentication Flags](#authentication-flags-available-for-scan-crawl-api) and [Rate Limiting Flags](#rate-limiting-flags-available-for-scan-crawl-api)

#### Examples

```bash
# Safe mode (default) - passive checks only
wast scan https://example.com

# Active testing (requires permission)
wast scan https://example.com --active

# Active testing with verification
wast scan https://example.com --active --verify

# Discovery mode - crawl then scan
wast scan https://example.com --discover --active --depth 3

# With authentication
wast scan https://api.example.com --bearer-token "YOUR_TOKEN"

# With rate limiting
wast scan https://example.com --active --rate-limit 2

# SARIF output for GitHub Code Scanning
wast scan https://example.com --output sarif > results.sarif

# Authenticated scan with login flow
export WAST_LOGIN_PASS="password123"
wast scan https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser \
  --active

# Show available capabilities (no target)
wast scan
```

#### Safe Mode vs Active Testing

**Safe Mode (Default)**:
- HTTP security headers analysis
- SSL/TLS configuration review
- Cookie security attributes
- CORS policy validation

**Active Testing (--active)**:
- Cross-Site Scripting (XSS) payload injection
- SQL Injection (SQLi) testing
- NoSQL Injection (NoSQLi) testing
- Command Injection (CMDi) testing
- Cross-Site Request Forgery (CSRF) token analysis
- Server-Side Request Forgery (SSRF) testing
- Open Redirect detection
- Path Traversal / Local File Inclusion (LFI) testing
- Server-Side Template Injection (SSTI) testing
- XML External Entity (XXE) injection testing

⚠️ **WARNING**: Active testing sends attack payloads. Only use on systems you own or have permission to test.

#### Output Structure

```json
{
  "success": true,
  "command": "scan",
  "message": "Security scan completed (active testing enabled)",
  "data": {
    "headers": {
      "findings": [
        {
          "severity": "high",
          "type": "missing_hsts",
          "rule_id": "WAST-HDR-001",
          "cwe": "CWE-693",
          "message": "Missing HTTP Strict Transport Security header",
          "remediation": "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        }
      ]
    },
    "xss": {
      "findings": [
        {
          "severity": "critical",
          "type": "reflected_xss",
          "rule_id": "WAST-XSS-001",
          "cwe": "CWE-79",
          "url": "https://example.com/search",
          "parameter": "q",
          "payload": "<script>alert(1)</script>",
          "verified": true,
          "confidence": "high"
        }
      ]
    },
    "sqli": {
      "findings": []
    },
    "csrf": {
      "findings": []
    },
    "ssrf": {
      "findings": []
    },
    "errors": []
  }
}
```

---

### wast crawl

Web crawling and content discovery.

#### Usage

```bash
wast crawl [target] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--depth` | integer | 3 | Maximum crawl depth (0 for unlimited) |
| `--timeout` | duration | 30s | Timeout for HTTP requests |
| `--user-agent` | string | WAST/1.0 | User agent string for requests |
| `--no-robots` | boolean | false | Ignore robots.txt rules |
| `--concurrency` | integer | 5 | Number of concurrent workers |

Plus: [Authentication Flags](#authentication-flags-available-for-scan-crawl-api) and [Rate Limiting Flags](#rate-limiting-flags-available-for-scan-crawl-api)

#### Examples

```bash
# Basic crawl
wast crawl https://example.com

# Deep crawl with high concurrency
wast crawl https://example.com --depth 5 --concurrency 10

# Ignore robots.txt
wast crawl https://example.com --no-robots

# Authenticated crawl with cookies
wast crawl https://app.example.com --cookies "session=abc123"

# Rate-limited crawl
wast crawl https://example.com --rate-limit 2 --depth 5

# Custom user agent
wast crawl https://example.com --user-agent "MyBot/1.0"

# JSON output
wast crawl https://example.com --output json

# Show available features (no target)
wast crawl
```

#### Output Structure

```json
{
  "success": true,
  "command": "crawl",
  "message": "Web crawl completed successfully",
  "data": {
    "urls": [
      "https://example.com/",
      "https://example.com/about",
      "https://example.com/contact",
      "https://example.com/api/users"
    ],
    "forms": [
      {
        "action": "/login",
        "method": "POST",
        "fields": ["username", "password"]
      }
    ],
    "static_resources": [
      "https://example.com/css/style.css",
      "https://example.com/js/app.js"
    ],
    "external_links": [
      "https://twitter.com/example"
    ],
    "robots_txt": {
      "user_agent": "*",
      "disallow": ["/admin", "/private"]
    },
    "errors": []
  }
}
```

---

### wast api

API discovery and security testing.

#### Usage

```bash
wast api [target] [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spec` | string | - | Path or URL to OpenAPI/Swagger specification |
| `--base-url` | string | - | Override the base URL from the specification |
| `--dry-run` | boolean | false | List endpoints without making requests |
| `--timeout` | integer | 30 | HTTP request timeout in seconds |
| `--respect-rate-limits` | boolean | false | Pause when rate limited (HTTP 429) |

Plus: [Authentication Flags](#authentication-flags-available-for-scan-crawl-api) and [Rate Limiting Flags](#rate-limiting-flags-available-for-scan-crawl-api)

#### Examples

```bash
# Parse OpenAPI spec (dry run)
wast api --spec openapi.yaml --dry-run

# Test API endpoints from spec
wast api --spec openapi.yaml --bearer-token "YOUR_TOKEN"

# Parse remote spec
wast api --spec https://api.example.com/openapi.json

# Override base URL
wast api --spec openapi.yaml --base-url https://staging.api.com

# API discovery on target
wast api https://api.example.com

# With rate limiting
wast api --spec openapi.yaml --rate-limit 5

# Respect server rate limits
wast api --spec openapi.yaml --respect-rate-limits

# JSON output
wast api https://api.example.com --output json

# Show available features (no target/spec)
wast api
```

#### Output Structure (Spec Parsing)

```json
{
  "success": true,
  "command": "api",
  "message": "API endpoints discovered (dry run)",
  "data": {
    "endpoints": [
      {
        "path": "/api/users",
        "method": "GET",
        "description": "List all users",
        "parameters": []
      },
      {
        "path": "/api/users/{id}",
        "method": "GET",
        "description": "Get user by ID",
        "parameters": ["id"]
      },
      {
        "path": "/api/users",
        "method": "POST",
        "description": "Create new user",
        "request_body": {
          "required": true,
          "content_type": "application/json"
        }
      }
    ],
    "summary": {
      "total_endpoints": 3,
      "tested_endpoints": 0
    }
  }
}
```

#### Output Structure (API Discovery)

```json
{
  "success": true,
  "command": "api",
  "message": "API discovery completed",
  "data": {
    "documentation_urls": [
      "https://api.example.com/swagger.json",
      "https://api.example.com/openapi.yaml"
    ],
    "api_endpoints": [
      "/api/v1/users",
      "/api/v1/products"
    ],
    "summary": {
      "endpoints_found": 2,
      "documentation_found": true
    }
  }
}
```

---

### wast intercept

Traffic interception and analysis with proxy server.

#### Usage

```bash
wast intercept [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port`, `-p` | integer | 8080 | Port to listen on |
| `--save`, `-s` | string | - | Save intercepted traffic to JSON file |
| `--init-ca` | boolean | false | Initialize CA certificate and exit |
| `--ca-cert` | string | - | Path to custom CA certificate file |
| `--ca-key` | string | - | Path to custom CA private key file |
| `--http-only` | boolean | false | Disable HTTPS interception |

#### Examples

```bash
# Start proxy on default port (8080)
wast intercept

# Use custom port
wast intercept --port 9090

# Save traffic to file
wast intercept --save traffic.json

# Initialize CA for HTTPS interception
wast intercept --init-ca

# Use custom CA certificate
wast intercept --ca-cert /path/to/ca.crt --ca-key /path/to/ca.key

# HTTP only (no HTTPS interception)
wast intercept --http-only

# JSON output for logged traffic
wast intercept --output json
```

#### HTTPS Interception Setup

1. **Initialize CA certificate:**
   ```bash
   wast intercept --init-ca
   ```

2. **Install the certificate in your browser/system:**
   - **Chrome**: Settings > Privacy > Security > Manage certificates > Authorities > Import
   - **Firefox**: Settings > Privacy & Security > Certificates > View Certificates > Import
   - **macOS**: Add to Keychain Access and trust for SSL
   - **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`

3. **Start the proxy with HTTPS interception:**
   ```bash
   wast intercept
   ```

4. **Configure your browser/application to use the proxy:**
   - Proxy host: `localhost`
   - Proxy port: `8080` (or your custom port)

#### Output Structure

```json
{
  "success": true,
  "command": "intercept",
  "message": "Proxy session completed",
  "data": {
    "requests_captured": 42,
    "duration": "120s",
    "save_file": "/tmp/traffic.json",
    "summary": {
      "total_requests": 42,
      "https_requests": 38,
      "http_requests": 4,
      "unique_hosts": 5
    },
    "requests": [
      {
        "method": "GET",
        "url": "https://example.com/api/users",
        "headers": {...},
        "body": null,
        "response": {
          "status": 200,
          "headers": {...},
          "body": "..."
        }
      }
    ]
  }
}
```

---

### wast serve

Start the MCP server for AI agent integration.

#### Usage

```bash
wast serve --mcp [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--mcp` | boolean | false | Start MCP server mode |
| `--telemetry-endpoint` | string | - | OpenTelemetry collector endpoint |

#### Examples

```bash
# Start MCP server
wast serve --mcp

# Or use the shorthand on root command
wast --mcp

# With OpenTelemetry tracing
export WAST_OTEL_ENDPOINT=localhost:4317
export WAST_OTEL_INSECURE=true
wast --mcp

# Or use CLI flag
wast --mcp --telemetry-endpoint localhost:4317
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `WAST_LOGIN_PASS` | Password for automated login (avoids shell history exposure) |
| `WAST_OTEL_ENDPOINT` | OpenTelemetry collector endpoint (e.g., localhost:4317) |
| `WAST_OTEL_SERVICE_NAME` | Service name for telemetry (default: "wast") |
| `WAST_OTEL_INSECURE` | Disable TLS for telemetry (use only in development) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid command or arguments |

## Output Formats

### Text Format (Default)

Human-readable output with colored indicators (when terminal supports it).

### JSON Format

Machine-readable JSON with consistent schema:

```json
{
  "success": true,
  "command": "scan",
  "message": "Security scan completed",
  "data": {...}
}
```

### YAML Format

Machine-readable YAML with same schema as JSON.

### SARIF Format

SARIF 2.1.0 compliant output for security tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [...]
}
```

---

### wast mcpscan scan

Scan MCP servers for security vulnerabilities. Servers can be supplied from a targets file (produced by `wast mcpscan discover`) or discovered inline.

#### Usage

```bash
wast mcpscan scan [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--targets` | string | - | Path to JSON file from `wast mcpscan discover --output json` |
| `--discover` | boolean | false | Discover MCP servers first, then scan them |
| `--network` | string | - | Domain or URL to probe for MCP endpoints (used with --discover) |
| `--deep` | boolean | false | Enumerate subdomains before probing (used with --discover --network) |
| `--concurrency` | integer | 5 | Number of servers to scan in parallel (use 1 for sequential) |
| `--open-only` | boolean | false | Skip servers that require authentication (filter out auth-required servers before scanning) |
| `--timeout` | integer | 30 | Per-request timeout in seconds (inherited from mcpscan parent) |
| `--active` | boolean | false | Enable active checks — sends potentially dangerous payloads (inherited from mcpscan parent) |

#### Examples

```bash
# Scan servers from a targets file (5 in parallel by default)
wast mcpscan scan --targets targets.json

# Scan with higher concurrency for large target lists
wast mcpscan scan --targets targets.json --concurrency 20

# Sequential scan (equivalent to the old behaviour)
wast mcpscan scan --targets targets.json --concurrency 1

# Active scan with custom concurrency
wast mcpscan scan --targets targets.json --active --concurrency 10

# Skip auth-required servers (useful for large fleets where credentials are unavailable)
wast mcpscan scan --targets targets.json --open-only

# All-in-one: discover and scan open servers only
wast mcpscan scan --discover --network example.com --deep --open-only --concurrency 10

# All-in-one: discover and scan
wast mcpscan scan --discover --network example.com --deep --concurrency 10
```

---

## Quick Reference

### Common Workflows

**Basic Security Assessment:**
```bash
wast recon example.com --subdomains --output json
wast crawl https://example.com --depth 5 --output json
wast scan https://example.com --output sarif > results.sarif
```

**Active Vulnerability Testing (with permission):**
```bash
wast scan https://example.com --active --verify --output sarif
```

**API Security Testing:**
```bash
wast api --spec openapi.yaml --dry-run
wast api --spec openapi.yaml --bearer-token "TOKEN" --output json
```

**Authenticated Testing:**
```bash
export WAST_LOGIN_PASS="password"
wast scan https://app.example.com --login-url https://app.example.com/login --login-user testuser --active
```

**Traffic Interception:**
```bash
wast intercept --init-ca
wast intercept --save traffic.json
```

## Additional Resources

- [Getting Started Guide](getting-started.md)
- [MCP Integration Guide](mcp-integration.md)
- [Authentication Guide](authentication.md)
- [Safe Mode Guide](safe-mode.md)
