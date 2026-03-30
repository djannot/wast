# Authentication Guide

This guide covers all authentication methods supported by WAST for testing protected web applications and APIs.

## Overview

WAST supports multiple authentication methods that can be used with the `scan`, `crawl`, and `api` commands:

1. **Bearer Token** - For API token authentication
2. **Basic Authentication** - For HTTP Basic Auth
3. **Custom Headers** - For custom authentication headers
4. **Cookies** - For session-based authentication
5. **Automated Login Flow** - For form-based authentication

Multiple authentication methods can be combined in a single request.

## Authentication Methods

### 1. Bearer Token Authentication

Bearer token authentication is commonly used with APIs that require JWT or OAuth tokens.

#### CLI Usage

```bash
# Scan with bearer token
wast scan https://api.example.com --bearer-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Crawl with bearer token
wast crawl https://api.example.com --bearer-token "YOUR_TOKEN"

# API testing with bearer token
wast api --spec openapi.yaml --bearer-token "YOUR_TOKEN"
```

#### MCP Usage

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://api.example.com",
    "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### How It Works

The bearer token is added to the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### 2. Basic Authentication

HTTP Basic Authentication sends credentials as a base64-encoded string in the `Authorization` header.

#### CLI Usage

```bash
# Scan with basic auth
wast scan https://example.com/admin --basic-auth "username:password"

# Crawl with basic auth
wast crawl https://example.com --basic-auth "admin:secretpass"

# API testing with basic auth
wast api https://api.example.com --basic-auth "apiuser:apikey"
```

#### MCP Usage

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://example.com/admin",
    "basic_auth": "username:password"
  }
}
```

#### How It Works

The credentials are base64-encoded and added to the `Authorization` header:

```
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

**Security Note**: Basic auth credentials are encoded (not encrypted). Always use HTTPS with basic authentication.

---

### 3. Custom Authentication Headers

For APIs that use custom authentication headers (e.g., `X-API-Key`, `X-Auth-Token`).

#### CLI Usage

```bash
# Scan with custom auth header
wast scan https://api.example.com --auth-header "X-API-Key: abc123xyz789"

# Multiple custom headers (use multiple flags)
wast scan https://api.example.com \
  --auth-header "X-API-Key: abc123" \
  --auth-header "X-Client-ID: client123"

# Custom Authorization header
wast scan https://api.example.com --auth-header "Authorization: ApiKey abc123"
```

#### MCP Usage

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://api.example.com",
    "auth_header": "X-API-Key: abc123xyz789"
  }
}
```

#### How It Works

The custom header is added exactly as specified:

```
X-API-Key: abc123xyz789
```

---

### 4. Cookie-Based Authentication

For session-based authentication where cookies maintain the authenticated state.

#### CLI Usage

```bash
# Scan with single cookie
wast scan https://app.example.com --cookies "session=abc123xyz"

# Scan with multiple cookies
wast scan https://app.example.com \
  --cookies "session=abc123xyz" \
  --cookies "user_id=456" \
  --cookies "auth_token=def789"

# Crawl with cookies
wast crawl https://app.example.com --cookies "PHPSESSID=abc123"
```

#### MCP Usage

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://app.example.com",
    "cookies": ["session=abc123xyz", "user_id=456", "auth_token=def789"]
  }
}
```

#### How Cookies Are Applied

Cookies are added to each request:

```
Cookie: session=abc123xyz; user_id=456; auth_token=def789
```

#### Extracting Cookies from Browser

**Chrome/Firefox Developer Tools:**
1. Open DevTools (F12)
2. Go to Application/Storage > Cookies
3. Copy the cookie name and value
4. Format as `name=value`

**Using curl:**
```bash
curl -c cookies.txt https://example.com/login -d "user=test&pass=test"
cat cookies.txt  # Extract cookie values
```

---

### 5. Automated Login Flow

WAST can automatically authenticate by submitting credentials to a login endpoint and capturing session cookies.

#### CLI Usage

**Recommended: Use Environment Variable for Password**

```bash
# Set password via environment variable (secure)
export WAST_LOGIN_PASS="password123"

# Scan with automated login
wast scan https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser

# Clear the password when done
unset WAST_LOGIN_PASS
```

**Alternative: Pass Password Directly (NOT RECOMMENDED)**

```bash
# WARNING: Exposes password in shell history
wast scan https://app.example.com/dashboard \
  --login-url https://app.example.com/login \
  --login-user testuser \
  --login-pass password123
```

#### Custom Field Names

If the login form uses different field names (e.g., `email` instead of `username`):

```bash
export WAST_LOGIN_PASS="secretpass"
wast scan https://app.example.com/admin \
  --login-url https://app.example.com/auth/login \
  --login-user admin@example.com \
  --login-user-field email \
  --login-pass-field pwd
```

#### MCP Usage

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://app.example.com/dashboard",
    "login_url": "https://app.example.com/login",
    "login_user": "testuser",
    "login_pass": "password123"
  }
}
```

⚠️ **WARNING**: When using MCP, credentials may be logged by MCP clients/servers. Consider using CLI with environment variables for sensitive credentials.

#### How Automated Login Works

1. WAST submits credentials to the login endpoint via POST request
2. The server responds with session cookies (and potentially redirects)
3. WAST captures these cookies automatically
4. Subsequent requests include the captured session cookies
5. WAST detects login failures (wrong status codes, error messages)

If no cookies are received, WAST automatically falls back to looking for a JWT bearer
token in the JSON response body (see [JWT-in-response-body Login](#jwt-in-response-body-login) below).

#### Supported Login Types

- **Form-based authentication** (default, `Content-Type: application/x-www-form-urlencoded`)
- **JSON API authentication** (`Content-Type: application/json`)
- **Redirects after successful login** (302/303 status codes)
- **JWT-in-response-body authentication** (automatic fallback when no cookies are received)

#### Login Flow Example

**Form-based login:**
```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

username=testuser&password=password123
```

**JSON API login:**
```http
POST /api/auth/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"username":"testuser","password":"password123"}
```

#### JWT-in-response-body Login

Many modern SPAs and REST APIs return a JWT bearer token in the JSON response body instead of
setting session cookies. WAST automatically detects this pattern as a fallback when no cookies
are received after a successful login.

The following well-known JSON fields are checked (in order):

| Field path | Example API |
|---|---|
| `token` | Generic REST APIs |
| `access_token` | OAuth2 token endpoint |
| `accessToken` | camelCase variant |
| `jwt` | Custom JWT field |
| `id_token` | OpenID Connect |
| `authentication.token` | OWASP Juice Shop |
| `data.token` | Nested data wrapper pattern |

You can also specify a custom dot-separated path with `token_field`:

**OWASP Juice Shop example (MCP):**

```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://juice-shop.example.com",
    "login_url": "https://juice-shop.example.com/rest/user/login",
    "login_user": "admin@juice-sh.op",
    "login_pass": "admin123",
    "login_content_type": "json",
    "login_token_field": "authentication.token"
  }
}
```

**OWASP Juice Shop example (CLI):**

```bash
export WAST_LOGIN_PASS="admin123"
wast scan https://juice-shop.example.com \
  --login-url https://juice-shop.example.com/rest/user/login \
  --login-user admin@juice-sh.op \
  --login-content-type json \
  --login-token-field "authentication.token"
```

The extracted token is used as a `Bearer` token in all subsequent requests:

```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Combining Authentication Methods

Multiple authentication methods can be combined in a single request. They are applied in this priority order (for the `Authorization` header):

1. **Basic Auth** (lowest priority)
2. **Custom Auth Header**
3. **Bearer Token** (highest priority)
4. **Cookies** (don't conflict with headers, always added)

### Example: Bearer Token + Cookies

```bash
# CLI
wast scan https://api.example.com \
  --bearer-token "eyJhbGci..." \
  --cookies "session=abc123"

# MCP
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://api.example.com",
    "bearer_token": "eyJhbGci...",
    "cookies": ["session=abc123"]
  }
}
```

This sends:
```
Authorization: Bearer eyJhbGci...
Cookie: session=abc123
```

### Example: Custom Header + Cookies

```bash
wast scan https://api.example.com \
  --auth-header "X-API-Key: abc123" \
  --cookies "session=xyz789"
```

---

## Security Best Practices

### 1. Avoid Exposing Credentials in Shell History

**DON'T:**
```bash
# BAD: Password exposed in shell history
wast scan https://app.example.com --login-pass "password123"
```

**DO:**
```bash
# GOOD: Use environment variable
export WAST_LOGIN_PASS="password123"
wast scan https://app.example.com --login-url https://app.example.com/login --login-user testuser
unset WAST_LOGIN_PASS
```

### 2. Use Unique Test Accounts

- Create dedicated test accounts with minimal privileges
- Never use production credentials for testing
- Rotate test credentials regularly

### 3. Secure Credential Storage

- Never hardcode credentials in scripts
- Use environment variables or secure credential managers
- Consider using temporary tokens instead of passwords

### 4. Network Security

- Always use HTTPS for authenticated requests
- Be aware that MCP parameters may be logged by clients/servers
- Avoid transmitting credentials over unencrypted connections

### 5. Test Environment Isolation

- Only use automated login for testing/development environments
- Never test against production systems without explicit permission
- Use separate authentication systems for test environments when possible

---

## Troubleshooting

### Login Flow Fails

**Check the login endpoint:**
```bash
# Test login manually with curl
curl -v -X POST https://app.example.com/login \
  -d "username=testuser&password=password123"
```

**Common issues:**
- Wrong login URL
- Incorrect field names (use `--login-user-field` and `--login-pass-field`)
- CSRF token required (not yet supported by WAST automated login)
- Rate limiting on login endpoint

### Cookies Not Working

**Verify cookie format:**
- Must be in `name=value` format
- No spaces around `=`
- Correct cookie name (case-sensitive)

**Check cookie expiration:**
- Cookies may have expired
- Re-extract fresh cookies from browser

**Check cookie domain:**
- Cookie must be valid for the target domain
- Subdomains may require different cookies

### Bearer Token Rejected

**Check token validity:**
- Token may have expired
- Token may be for wrong audience/scope
- Token format may be incorrect

**Verify token format:**
```bash
# JWT tokens are base64-encoded with 3 parts separated by dots
echo "eyJhbGci..." | cut -d. -f2 | base64 -d
```

### Basic Auth Not Working

**Check credentials:**
- Username and password must be correct
- Use colon separator: `user:pass`
- Special characters in password may need escaping

**Verify server supports basic auth:**
```bash
curl -v -u username:password https://example.com/admin
```

---

## Examples by Use Case

### Testing a Microservice API

```bash
# With JWT token
wast scan https://api.example.com/v1/users \
  --bearer-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output json
```

### Testing a SPA (Single Page Application)

```bash
# Login flow + scan
export WAST_LOGIN_PASS="password123"
wast crawl https://app.example.com \
  --login-url https://app.example.com/api/login \
  --login-user testuser \
  --depth 5
```

### Testing an Admin Panel

```bash
# Basic auth + scan
wast scan https://example.com/admin \
  --basic-auth "admin:adminpass" \
  --active \
  --output sarif
```

### Testing with API Key

```bash
# Custom header auth
wast api https://api.example.com \
  --auth-header "X-API-Key: abc123xyz789" \
  --spec https://api.example.com/openapi.json
```

### Testing with Multiple Auth Methods

```bash
# Bearer token + cookies + custom header
wast scan https://api.example.com \
  --bearer-token "eyJhbGci..." \
  --cookies "session=abc123" \
  --auth-header "X-Client-ID: client123" \
  --active
```

---

## Authentication in Different Commands

### wast scan

All authentication methods supported. Example:

```bash
wast scan https://app.example.com \
  --login-url https://app.example.com/login \
  --login-user testuser \
  --active \
  --discover
```

### wast crawl

All authentication methods supported. Example:

```bash
wast crawl https://app.example.com \
  --cookies "session=abc123" \
  --depth 5 \
  --concurrency 10
```

### wast api

All authentication methods supported. Example:

```bash
wast api --spec openapi.yaml \
  --bearer-token "YOUR_TOKEN" \
  --base-url https://staging.api.com
```

### wast recon

Authentication not applicable (DNS and TLS operations don't require HTTP authentication).

### wast intercept

Authentication not applicable (proxy mode doesn't make requests itself).

---

## Additional Resources

- [Getting Started Guide](getting-started.md)
- [CLI Reference](cli-reference.md)
- [MCP Integration Guide](mcp-integration.md)
- [Safe Mode Guide](safe-mode.md)

## Related Topics

- Rate Limiting: See [CLI Reference](cli-reference.md#rate-limiting-flags-available-for-scan-crawl-api)
- Output Formats: See [Getting Started Guide](getting-started.md#output-formats)
- Active Testing: See [Safe Mode Guide](safe-mode.md)
