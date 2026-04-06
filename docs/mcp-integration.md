# MCP Integration Guide

This guide provides comprehensive documentation for integrating WAST with AI agents using the Model Context Protocol (MCP).

## Overview

WAST implements the MCP (Model Context Protocol) specification to enable seamless integration with AI assistants like Claude. The MCP server exposes WAST's security testing capabilities as standardized tools that can be invoked through natural language or direct JSON-RPC calls.

### Protocol Details

- **Protocol**: JSON-RPC 2.0
- **Specification**: [MCP Specification](https://spec.modelcontextprotocol.io/)
- **Protocol Version**: 2024-11-05
- **Transports**:
  - `stdio` (default) — standard input/output; required for desktop MCP clients
  - `http` — Streamable HTTP (`POST /mcp`); recommended for networked / containerised deployments

## Error Handling

WAST follows the MCP specification for error handling, distinguishing between two kinds of failures:

### Protocol-level errors (JSON-RPC errors)

These are returned as standard JSON-RPC error responses and indicate problems at the transport or protocol level — not tool execution failures. AI agent clients should treat these as unrecoverable for the specific request.

| Code    | Meaning           | When it occurs |
|---------|-------------------|----------------|
| `-32700` | Parse error       | The request body is not valid JSON |
| `-32600` | Invalid request   | The JSON-RPC envelope is malformed (e.g. wrong `jsonrpc` version) |
| `-32601` | Method not found  | The requested method (e.g. `unknown/method`) does not exist |
| `-32602` | Invalid params    | Required params are missing or the params JSON cannot be decoded |

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": "target is required"
  }
}
```

### Tool execution errors (`isError: true`)

When a tool's execution fails (e.g. the target is unreachable, a scan times out, or required arguments are semantically invalid), the server returns a **successful** JSON-RPC response whose result contains `"isError": true` and a human-readable error message in the content array.

This design lets AI agent clients reason about the failure, adjust their strategy, and potentially retry with different parameters — exactly as they would handle a tool that returns an error finding.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "target is required"
      }
    ],
    "isError": true
  }
}
```

AI agents should inspect `result.isError` after every `tools/call` response and treat a `true` value as a tool-level failure that may be retried or reported to the user.

---

## Starting the MCP Server

### Stdio transport (default)

The default transport uses standard input/output (stdio), which is required by MCP desktop clients such as Claude Desktop.

```bash
# Start MCP server (stdio)
wast serve --mcp

# With OpenTelemetry tracing
export WAST_OTEL_ENDPOINT=localhost:4317
wast --mcp --telemetry-endpoint localhost:4317
```

### Streamable HTTP transport

The Streamable HTTP transport (MCP spec 2024-11-05+) exposes WAST as a networked service. This enables remote AI agent integration, containerised deployment, and shared-service architectures.

```bash
# Start MCP server over HTTP on the default address (:8080)
wast serve --mcp --transport http

# Start on a custom address
wast serve --mcp --transport http --addr :9090

# Start on a specific interface
wast serve --mcp --transport http --addr 0.0.0.0:8080
```

#### HTTP endpoint

All JSON-RPC requests must be sent as `POST /mcp`.

```bash
# Send an initialize request
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}'
```

#### Session management

The server issues a `Mcp-Session-Id` response header on every reply. Include this header in subsequent requests to maintain session context:

```bash
SESSION_ID=$(curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  -D - | grep -i mcp-session-id | awk '{print $2}' | tr -d '\r')

# Use the session ID in follow-up requests
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

#### Streaming (Server-Sent Events)

Set `Accept: text/event-stream` to receive progress notifications during long-running scans as SSE events:

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wast_recon","arguments":{"target":"example.com"}}}'
```

Each event is delivered as:

```
data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"phase":"dns","completed":0,"total":0,"message":"Running DNS enumeration"}}

data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"..."}]}}

```

#### Rate limiting and concurrency control

The HTTP transport includes built-in rate limiting and concurrency control to protect the server from resource exhaustion.

**Rate limiting** (`--rate-limit`) caps the number of inbound requests accepted per second using a token-bucket algorithm. Requests that exceed the limit receive HTTP 429 with a `Retry-After: 1` header.

**Concurrency limiting** (`--max-concurrent`) caps the number of concurrent requests to the `/mcp` endpoint that may run simultaneously. This applies to all request types (`initialize`, `tools/list`, `tools/call`, etc.). Requests that would exceed the limit are rejected immediately with HTTP 429 and a `Retry-After` header.

```bash
# Use default limits (10 req/s, 5 concurrent)
wast serve --mcp --transport http

# Higher limits for a trusted internal deployment
wast serve --mcp --transport http --rate-limit 50 --max-concurrent 20

# Disable both limits (not recommended for public endpoints)
wast serve --mcp --transport http --rate-limit 0 --max-concurrent 0
```

| Flag | Default | Description |
|------|---------|-------------|
| `--rate-limit` | `10` | Maximum inbound requests per second (0 = disabled) |
| `--max-concurrent` | `5` | Maximum concurrent requests to `/mcp` (0 = disabled) |

#### CORS support for browser-based clients

By default, the HTTP transport sets no CORS headers. To allow browser-based MCP clients (web UIs, browser extensions, etc.) to reach the server, pass `--cors-origin`:

```bash
# Allow all origins (development / open access)
wast serve --mcp --transport http --cors-origin "*"

# Allow a specific origin (production)
wast serve --mcp --transport http --cors-origin "https://myapp.example.com"
```

When configured, the server:
- Responds to `OPTIONS` preflight requests with `204 No Content` and the appropriate `Access-Control-Allow-*` headers.
- Adds `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers: Mcp-Session-Id` to all `POST` responses so browsers can read the session header.

#### Docker / container deployment

```dockerfile
FROM debian:bookworm-slim
COPY wast /usr/local/bin/wast
EXPOSE 8080
CMD ["wast", "serve", "--mcp", "--transport", "http", "--addr", ":8080"]
```

```yaml
# docker-compose.yml
services:
  wast-mcp:
    image: wast:latest
    ports:
      - "8080:8080"
    command: ["serve", "--mcp", "--transport", "http", "--addr", ":8080"]
```

## MCP Tools Reference

WAST provides 8 MCP tools for security testing. All tools respect WAST's safe mode defaults.

### 1. wast_recon - Reconnaissance

Perform reconnaissance on a target domain including DNS enumeration, subdomain discovery, and TLS certificate analysis.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | Target domain to perform reconnaissance on |
| `timeout` | string | No | "10s" | Timeout for DNS queries (e.g., '10s', '1m') |
| `include_subdomains` | boolean | No | false | Enable subdomain discovery via CT logs and zone transfer |

#### JSON-RPC Request Example

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "wast_recon",
    "arguments": {
      "target": "example.com",
      "timeout": "30s",
      "include_subdomains": true
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"target\":\"example.com\",\"dns\":{\"a_records\":[\"93.184.216.34\"],\"aaaa_records\":[\"2606:2800:220:1:248:1893:25c8:1946\"],\"mx_records\":[\"mail.example.com\"],\"ns_records\":[\"ns1.example.com\",\"ns2.example.com\"],\"txt_records\":[\"v=spf1 ...\"],\"subdomains\":[\"www.example.com\",\"api.example.com\"]},\"tls\":{\"version\":\"TLS 1.3\",\"cipher_suite\":\"TLS_AES_256_GCM_SHA384\",\"certificate\":{\"subject\":\"CN=example.com\",\"issuer\":\"Let's Encrypt\",\"valid_from\":\"2024-01-01\",\"valid_until\":\"2024-04-01\",\"san\":[\"example.com\",\"www.example.com\"]}}}"
      }
    ]
  }
}
```

#### Error Response Example

When the tool cannot execute (e.g. a required argument is missing or invalid), the server returns a **successful** JSON-RPC response with `isError: true`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "target is required"
      }
    ],
    "isError": true
  }
}
```

---

### 2. wast_scan - Security Scanning

Run security vulnerability scans on a target. Defaults to safe mode (passive checks only).

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | Target URL to scan |
| `timeout` | integer | No | 30 | HTTP request timeout in seconds |
| `active` | boolean | No | false | Enable active vulnerability testing (SQLi, XSS, CSRF, SSRF) |
| `verify` | boolean | No | false | Enable finding verification to reduce false positives |
| `discover` | boolean | No | false | First crawl to discover forms/endpoints, then scan all discovered attack surfaces |
| `depth` | integer | No | 2 | Maximum crawl depth for discovery mode (used with discover=true) |
| `concurrency` | integer | No | 5 | Number of concurrent workers for crawl phase (used with discover=true) |
| `scan_concurrency` | integer | No | 5 | Number of concurrent workers for scanning (used with discover=true) |
| `bearer_token` | string | No | - | Bearer token for Authorization header |
| `basic_auth` | string | No | - | Basic auth credentials in format 'user:pass' |
| `auth_header` | string | No | - | Custom auth header in format 'HeaderName: Value' |
| `cookies` | array[string] | No | - | Cookies to include in requests (format: 'name=value') |
| `login_url` | string | No | - | Login endpoint URL for automated authentication |
| `login_user` | string | No | - | Username for automated login |
| `login_pass` | string | No | - | Password for automated login (WARNING: visible in MCP logs) |
| `login_user_field` | string | No | "username" | Form field name for username |
| `login_pass_field` | string | No | "password" | Form field name for password |
| `requests_per_second` | number | No | 0 | Rate limit for requests per second (0 for unlimited) |

#### JSON-RPC Request Example (Safe Mode)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "wast_scan",
    "arguments": {
      "target": "https://example.com",
      "timeout": 60
    }
  }
}
```

#### JSON-RPC Request Example (Active Testing)

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "wast_scan",
    "arguments": {
      "target": "https://example.com",
      "active": true,
      "verify": true,
      "timeout": 60,
      "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

#### JSON-RPC Request Example (Discovery Mode)

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "wast_scan",
    "arguments": {
      "target": "https://example.com",
      "discover": true,
      "active": true,
      "depth": 3,
      "concurrency": 10,
      "scan_concurrency": 5
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"headers\":{\"findings\":[{\"severity\":\"high\",\"type\":\"missing_hsts\",\"message\":\"Missing HTTP Strict Transport Security header\",\"remediation\":\"Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains\"}]},\"xss\":{\"findings\":[{\"severity\":\"critical\",\"url\":\"https://example.com/search?q=test\",\"parameter\":\"q\",\"payload\":\"<script>alert(1)</script>\",\"verified\":true}]},\"sqli\":{\"findings\":[]},\"csrf\":{\"findings\":[]},\"ssrf\":{\"findings\":[]}}"
      }
    ]
  }
}
```

---

### 3. wast_crawl - Web Crawling

Crawl a web application to discover URLs, endpoints, and content.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | Target URL to crawl |
| `depth` | integer | No | 3 | Maximum crawl depth (0 for unlimited) |
| `timeout` | string | No | "30s" | Timeout for HTTP requests (e.g., '30s', '1m') |
| `respect_robots` | boolean | No | true | Respect robots.txt rules |
| `concurrency` | integer | No | 5 | Number of concurrent workers for crawling |
| `bearer_token` | string | No | - | Bearer token for Authorization header |
| `basic_auth` | string | No | - | Basic auth credentials in format 'user:pass' |
| `auth_header` | string | No | - | Custom auth header in format 'HeaderName: Value' |
| `cookies` | array[string] | No | - | Cookies to include in requests (format: 'name=value') |
| `login_url` | string | No | - | Login endpoint URL for automated authentication |
| `login_user` | string | No | - | Username for automated login |
| `login_pass` | string | No | - | Password for automated login |
| `login_user_field` | string | No | "username" | Form field name for username |
| `login_pass_field` | string | No | "password" | Form field name for password |
| `requests_per_second` | number | No | 0 | Rate limit for requests per second (0 for unlimited) |

#### JSON-RPC Request Example

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "wast_crawl",
    "arguments": {
      "target": "https://example.com",
      "depth": 5,
      "timeout": "60s",
      "respect_robots": true,
      "concurrency": 10,
      "cookies": ["session=abc123", "user_id=456"]
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"urls\":[\"https://example.com/\",\"https://example.com/about\",\"https://example.com/contact\",\"https://example.com/api/users\"],\"forms\":[{\"action\":\"/login\",\"method\":\"POST\",\"fields\":[\"username\",\"password\"]}],\"static_resources\":[\"https://example.com/css/style.css\",\"https://example.com/js/app.js\"],\"external_links\":[\"https://twitter.com/example\"]}"
      }
    ]
  }
}
```

---

### 4. wast_api - API Testing

Discover and test API endpoints. Can parse OpenAPI/Swagger specifications or perform API discovery.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | No* | - | Target URL for API discovery (optional if spec_file is provided) |
| `spec_file` | string | No* | - | Path or URL to OpenAPI/Swagger specification |
| `dry_run` | boolean | No | false | List endpoints without making requests |
| `timeout` | integer | No | 30 | HTTP request timeout in seconds |
| `bearer_token` | string | No | - | Bearer token for Authorization header |
| `basic_auth` | string | No | - | Basic auth credentials in format 'user:pass' |
| `auth_header` | string | No | - | Custom auth header in format 'HeaderName: Value' |
| `cookies` | array[string] | No | - | Cookies to include in requests (format: 'name=value') |
| `login_url` | string | No | - | Login endpoint URL for automated authentication |
| `login_user` | string | No | - | Username for automated login |
| `login_pass` | string | No | - | Password for automated login |
| `login_user_field` | string | No | "username" | Form field name for username |
| `login_pass_field` | string | No | "password" | Form field name for password |
| `requests_per_second` | number | No | 0 | Rate limit for requests per second (0 for unlimited) |

*Note: Either `target` or `spec_file` is required.

#### JSON-RPC Request Example (Spec Parsing)

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "wast_api",
    "arguments": {
      "spec_file": "https://petstore.swagger.io/v2/swagger.json",
      "dry_run": true
    }
  }
}
```

#### JSON-RPC Request Example (API Discovery)

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "wast_api",
    "arguments": {
      "target": "https://api.example.com",
      "bearer_token": "YOUR_API_TOKEN",
      "timeout": 60
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"endpoints\":[{\"path\":\"/api/users\",\"method\":\"GET\",\"description\":\"List all users\"},{\"path\":\"/api/users/{id}\",\"method\":\"GET\",\"description\":\"Get user by ID\"},{\"path\":\"/api/users\",\"method\":\"POST\",\"description\":\"Create new user\"}],\"summary\":{\"total_endpoints\":3,\"tested_endpoints\":0}}"
      }
    ]
  }
}
```

---

### 5. wast_intercept - Traffic Interception

Start a proxy server to intercept and analyze HTTP/HTTPS traffic.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `port` | integer | No | 8080 | Port to listen on for the proxy |
| `duration` | string | No | "60s" | Duration to capture traffic (e.g., '30s', '5m') |
| `save_file` | string | No | - | Path to save intercepted traffic as JSON |
| `https_interception` | boolean | No | false | Enable HTTPS traffic interception (requires CA setup) |
| `max_requests` | integer | No | - | Stop after capturing N requests (alternative to duration) |

#### JSON-RPC Request Example

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "wast_intercept",
    "arguments": {
      "port": 8080,
      "duration": "120s",
      "save_file": "/tmp/traffic.json",
      "https_interception": true,
      "max_requests": 100
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"requests_captured\":42,\"duration\":\"120s\",\"save_file\":\"/tmp/traffic.json\",\"summary\":{\"total_requests\":42,\"https_requests\":38,\"http_requests\":4}}"
      }
    ]
  }
}
```

---

### 6. wast_headers - Security Header Analysis

Perform passive-only security header analysis. Checks HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), cookie security attributes, and CORS policy configuration. This is a lightweight alternative to wast_scan when you only need header analysis.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | Target URL to scan for security headers |
| `timeout` | integer | No | 30 | HTTP request timeout in seconds |
| `bearer_token` | string | No | - | Bearer token for Authorization header |
| `basic_auth` | string | No | - | Basic auth credentials in format 'user:pass' |
| `auth_header` | string | No | - | Custom auth header in format 'HeaderName: Value' |
| `cookies` | array[string] | No | - | Cookies to include in requests (format: 'name=value') |
| `requests_per_second` | number | No | 0 | Rate limit for requests per second (0 for unlimited) |

*Note: Unlike `wast_scan`, `wast_crawl`, and `wast_api`, this tool does NOT support login flow parameters.*

#### JSON-RPC Request Example

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "wast_headers",
    "arguments": {
      "target": "https://example.com",
      "timeout": 30,
      "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"target\":\"https://example.com\",\"headers\":[{\"name\":\"Strict-Transport-Security\",\"present\":true,\"value\":\"max-age=31536000; includeSubDomains\",\"severity\":\"info\",\"description\":\"HSTS header is present\"},{\"name\":\"X-Content-Type-Options\",\"present\":true,\"value\":\"nosniff\",\"severity\":\"info\",\"description\":\"X-Content-Type-Options header is present\"},{\"name\":\"X-Frame-Options\",\"present\":false,\"severity\":\"medium\",\"description\":\"X-Frame-Options header is missing\",\"remediation\":\"Add X-Frame-Options header with value DENY or SAMEORIGIN\"},{\"name\":\"Content-Security-Policy\",\"present\":false,\"severity\":\"high\",\"description\":\"Content-Security-Policy header is missing\",\"remediation\":\"Implement a Content-Security-Policy header\"}],\"cookies\":[{\"name\":\"session\",\"http_only\":true,\"secure\":true,\"same_site\":\"Strict\",\"issues\":[],\"severity\":\"info\"},{\"name\":\"tracking\",\"http_only\":false,\"secure\":false,\"same_site\":\"None\",\"issues\":[\"Missing HttpOnly flag\",\"Missing Secure flag\"],\"severity\":\"medium\",\"remediation\":\"Set HttpOnly and Secure flags on cookie\"}],\"cors\":[{\"header\":\"Access-Control-Allow-Origin\",\"value\":\"*\",\"present\":true,\"issues\":[\"Wildcard origin allows all domains\"],\"severity\":\"medium\",\"description\":\"CORS policy allows all origins\",\"remediation\":\"Restrict Access-Control-Allow-Origin to specific trusted domains\"}],\"summary\":{\"total_headers\":7,\"missing_headers\":2,\"total_cookies\":2,\"insecure_cookies\":1,\"cors_issues\":1,\"high_severity_count\":1,\"medium_severity_count\":2,\"low_severity_count\":0,\"info_count\":3}}"
      }
    ]
  }
}
```

---

### 7. wast_verify - Finding Verification

Verify individual security findings before reporting them. Re-tests findings with payload variants to reduce false positives. Supports verification of SQLi, XSS, SSRF, CMDi, Path Traversal, Redirect, and CSRF findings.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `finding_type` | string | Yes | - | Type of finding to verify (sqli, xss, ssrf, cmdi, pathtraversal, redirect, csrf) |
| `finding_url` | string | Yes | - | URL where the finding was detected |
| `parameter` | string | Yes | - | Vulnerable parameter name |
| `payload` | string | Yes | - | Original payload that triggered the finding |
| `max_retries` | integer | No | 3 | Maximum verification attempts |
| `delay` | string | No | "100ms" | Delay between verification attempts (e.g., '100ms', '1s') |
| `bearer_token` | string | No | - | Bearer token for Authorization header |
| `basic_auth` | string | No | - | Basic auth credentials in format 'user:pass' |
| `auth_header` | string | No | - | Custom auth header in format 'HeaderName: Value' |
| `cookies` | array[string] | No | - | Cookies to include in requests (format: 'name=value') |
| `login_url` | string | No | - | Login endpoint URL for automated authentication |
| `login_user` | string | No | - | Username for automated login |
| `login_pass` | string | No | - | Password for automated login (WARNING: visible in MCP logs) |
| `login_user_field` | string | No | "username" | Form field name for username |
| `login_pass_field` | string | No | "password" | Form field name for password |
| `requests_per_second` | number | No | 0 | Rate limit for requests per second (0 for unlimited) |

#### Valid Finding Types

- `sqli` - SQL Injection
- `xss` - Cross-Site Scripting
- `ssrf` - Server-Side Request Forgery
- `cmdi` - Command Injection
- `pathtraversal` - Path Traversal
- `redirect` - Open Redirect
- `csrf` - Cross-Site Request Forgery

#### JSON-RPC Request Example

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "wast_verify",
    "arguments": {
      "finding_type": "xss",
      "finding_url": "https://example.com/search",
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "max_retries": 3,
      "delay": "100ms",
      "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"finding_type\":\"xss\",\"finding_url\":\"https://example.com/search\",\"parameter\":\"q\",\"original_payload\":\"<script>alert(1)</script>\",\"verified\":true,\"confidence\":\"high\",\"attempts\":2,\"verification_details\":{\"payload_variants_tested\":3,\"successful_variants\":2,\"response_indicators\":[\"payload reflected in response\",\"no encoding applied\"]},\"recommendation\":\"Implement proper output encoding and Content Security Policy\"}"
      }
    ]
  }
}
```

---

### 8. wast_websocket - WebSocket Security Scanning

Perform WebSocket security scanning on a target. Detects WebSocket endpoints and scans for security issues including insecure protocols (ws:// vs wss://) and missing origin validation (CSWSH). Defaults to passive mode.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | Target URL to scan for WebSocket endpoints |
| `active` | boolean | No | false | Enable active testing for origin validation (CSWSH detection) |
| `timeout` | integer | No | 30 | HTTP request timeout in seconds |
| `bearer_token` | string | No | - | Bearer token for Authorization header |
| `basic_auth` | string | No | - | Basic auth credentials in format 'user:pass' |
| `auth_header` | string | No | - | Custom auth header in format 'HeaderName: Value' |
| `cookies` | array[string] | No | - | Cookies to include in requests (format: 'name=value') |
| `requests_per_second` | number | No | 0 | Rate limit for requests per second (0 for unlimited) |

*Note: Unlike some other tools, `wast_websocket` does NOT support login flow parameters. Use static authentication (tokens, cookies) instead.*

#### Security Checks Performed

- **Insecure Protocol Detection**: Identifies WebSocket endpoints using unencrypted `ws://` protocol instead of secure `wss://`
- **Cross-Site WebSocket Hijacking (CSWSH)**: In active mode, tests for missing origin validation that could allow attackers to hijack WebSocket connections

#### JSON-RPC Request Example (Passive Mode)

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tools/call",
  "params": {
    "name": "wast_websocket",
    "arguments": {
      "target": "https://example.com",
      "timeout": 30,
      "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

#### JSON-RPC Request Example (Active Mode)

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "tools/call",
  "params": {
    "name": "wast_websocket",
    "arguments": {
      "target": "https://example.com",
      "active": true,
      "timeout": 60,
      "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "cookies": ["session=abc123"]
    }
  }
}
```

#### Expected Response

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"target\":\"https://example.com\",\"endpoints\":[{\"url\":\"ws://example.com/chat\",\"protocol\":\"ws\",\"page\":\"https://example.com/chat\",\"issues\":[{\"severity\":\"high\",\"type\":\"insecure_protocol\",\"message\":\"WebSocket connection uses insecure ws:// protocol\",\"remediation\":\"Use wss:// (WebSocket Secure) instead of ws:// to encrypt WebSocket traffic\"}]},{\"url\":\"wss://example.com/notifications\",\"protocol\":\"wss\",\"page\":\"https://example.com/dashboard\",\"issues\":[]}],\"findings\":[{\"severity\":\"high\",\"endpoint\":\"ws://example.com/chat\",\"type\":\"insecure_protocol\",\"message\":\"Insecure WebSocket protocol detected\",\"cswsh_vulnerable\":false}],\"summary\":{\"total_endpoints\":2,\"insecure_endpoints\":1,\"cswsh_vulnerable\":0,\"high_severity\":1,\"medium_severity\":0,\"low_severity\":0}}"
      }
    ]
  }
}
```

---

## Error Handling

### Standard JSON-RPC Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON was received |
| -32600 | Invalid Request | The JSON-RPC request is not valid |
| -32601 | Method not found | The method does not exist |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal JSON-RPC error |

### Error Response Example

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": "target is required"
  }
}
```

### Common Error Scenarios

#### Missing Required Parameter

```json
{
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": "target is required"
  }
}
```

#### Invalid Parameter Type

```json
{
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": "invalid arguments: json: cannot unmarshal string into Go value of type int"
  }
}
```

#### Tool Execution Failure

```json
{
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": "automated login failed: invalid credentials"
  }
}
```

## Rate Limiting

All tools that perform HTTP requests support rate limiting via the `requests_per_second` parameter:

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://example.com",
    "requests_per_second": 2.5
  }
}
```

- `0` (default): Unlimited requests
- `> 0`: Maximum requests per second (supports fractional values)

## Authentication in MCP

All HTTP-based tools (`wast_scan`, `wast_crawl`, `wast_api`, `wast_headers`) support authentication parameters. See [Authentication Guide](authentication.md) for detailed examples.

### Quick Example

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://app.example.com",
    "bearer_token": "eyJhbGciOi...",
    "cookies": ["session=abc123", "user_id=456"]
  }
}
```

## MCP Initialization Flow

### 1. Initialize Request

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "claude-desktop",
      "version": "1.0.0"
    }
  }
}
```

### 2. Initialize Response

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "result": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "wast",
      "version": "1.0.0"
    },
    "capabilities": {
      "tools": {}
    }
  }
}
```

### 3. List Tools Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

### 4. List Tools Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "wast_recon",
        "description": "Perform reconnaissance on a target domain...",
        "inputSchema": {
          "type": "object",
          "properties": {...},
          "required": ["target"]
        }
      },
      ...
    ]
  }
}
```

## OpenTelemetry Integration

WAST supports OpenTelemetry tracing for observability:

```bash
# Enable tracing with environment variable
export WAST_OTEL_ENDPOINT=localhost:4317
export WAST_OTEL_INSECURE=true  # For local development only
wast --mcp

# Or use CLI flag
wast --mcp --telemetry-endpoint localhost:4317
```

All tool invocations will emit spans for major operations, enabling performance monitoring and debugging.

## Bulk MCP Server Scanning

For scanning large numbers of MCP servers (e.g., from a registry export), use the two-step workflow:

```bash
# 1. Discover servers and save to a file
wast mcpscan discover --network example.com --deep --output json > targets.json

# 2. Scan all discovered servers in parallel
wast mcpscan scan --targets targets.json --concurrency 20
```

The `--concurrency` flag controls how many servers are scanned simultaneously:

| Value | Behaviour |
|-------|-----------|
| `1` | Sequential scan — identical to the previous behaviour |
| `5` | Default — safe for most networks |
| `10–20` | Recommended for large target lists on fast networks |

Progress lines are serialised by a mutex, so output remains readable even at high concurrency.

## Best Practices

1. **Safe by Default**: All tools respect safe mode defaults. Use `active=true` only with explicit permission.

2. **Rate Limiting**: Always set appropriate `requests_per_second` values to avoid overwhelming target systems or triggering rate limits.

3. **Credential Security**: Avoid passing sensitive credentials in MCP parameters when possible. Consider using CLI with environment variables instead.

4. **Error Handling**: Always check for error responses and handle them gracefully in your AI agent.

5. **Timeout Configuration**: Set appropriate timeout values based on your network conditions and target responsiveness.

6. **Discovery Before Scanning**: Use `discover=true` in `wast_scan` to find all attack surfaces before testing.

7. **Bulk Concurrency**: When scanning many MCP servers with `wast mcpscan scan`, use `--concurrency` to scan in parallel. Start with the default (5) and increase as your network allows.

## Troubleshooting

### MCP Server Not Starting

- Check that the binary is executable: `chmod +x /path/to/wast`
- Verify the path in your MCP client configuration
- Check logs for initialization errors

### Tool Execution Timeouts

- Increase the `timeout` parameter
- Reduce `concurrency` to avoid overwhelming the target
- Enable rate limiting with `requests_per_second`

### Authentication Failures

- Verify credentials are correct
- Check that the authentication method matches the target's requirements
- For login flows, verify the form field names match the actual form

## Additional Resources

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [CLI Reference](cli-reference.md)
- [Authentication Guide](authentication.md)
- [Safe Mode Guide](safe-mode.md)
