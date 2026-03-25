# MCP Integration Guide

This guide provides comprehensive documentation for integrating WAST with AI agents using the Model Context Protocol (MCP).

## Overview

WAST implements the MCP (Model Context Protocol) specification to enable seamless integration with AI assistants like Claude. The MCP server exposes WAST's security testing capabilities as standardized tools that can be invoked through natural language or direct JSON-RPC calls.

### Protocol Details

- **Protocol**: JSON-RPC 2.0 over stdio
- **Specification**: [MCP Specification](https://spec.modelcontextprotocol.io/)
- **Protocol Version**: 2024-11-05
- **Transport**: Standard input/output (stdio)

## Starting the MCP Server

```bash
# Start MCP server
wast serve --mcp

# Or use the shorthand flag
wast --mcp

# With OpenTelemetry tracing
export WAST_OTEL_ENDPOINT=localhost:4317
wast --mcp --telemetry-endpoint localhost:4317
```

## MCP Tools Reference

WAST provides 6 MCP tools for security testing. All tools respect WAST's safe mode defaults.

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

## Best Practices

1. **Safe by Default**: All tools respect safe mode defaults. Use `active=true` only with explicit permission.

2. **Rate Limiting**: Always set appropriate `requests_per_second` values to avoid overwhelming target systems or triggering rate limits.

3. **Credential Security**: Avoid passing sensitive credentials in MCP parameters when possible. Consider using CLI with environment variables instead.

4. **Error Handling**: Always check for error responses and handle them gracefully in your AI agent.

5. **Timeout Configuration**: Set appropriate timeout values based on your network conditions and target responsiveness.

6. **Discovery Before Scanning**: Use `discover=true` in `wast_scan` to find all attack surfaces before testing.

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
