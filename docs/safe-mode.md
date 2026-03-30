# Safe Mode Guide

This guide explains WAST's safe mode feature, which protects against accidental active vulnerability testing.

## Overview

**WAST runs in safe mode by default** to prevent accidental active vulnerability testing against systems you don't own or have permission to test. This design choice prioritizes responsible security testing and legal compliance.

## Safe Mode vs Active Testing

### Safe Mode (Default)

Safe mode performs **only passive security checks** that analyze server responses without sending potentially dangerous payloads.

#### What Safe Mode Does

✅ **HTTP Security Headers Analysis**
- Checks for HSTS (HTTP Strict Transport Security)
- Validates Content Security Policy (CSP)
- Checks X-Frame-Options
- Validates X-Content-Type-Options
- Checks Referrer-Policy
- Validates Permissions-Policy

✅ **SSL/TLS Configuration Review**
- TLS version analysis
- Cipher suite evaluation
- Certificate validation
- Certificate chain analysis
- Certificate expiration checking

✅ **Cookie Security Attributes**
- HttpOnly flag validation
- Secure flag validation
- SameSite attribute checking
- Cookie expiration analysis

✅ **CORS Policy Validation**
- Access-Control-Allow-Origin analysis
- Wildcard origin detection
- Credential exposure checks

#### What Safe Mode Does NOT Do

❌ **No Active Vulnerability Testing**
- No XSS (Cross-Site Scripting) payload injection
- No SQLi (SQL Injection) testing
- No NoSQLi (NoSQL Injection) testing
- No CMDi (Command Injection) testing
- No CSRF (Cross-Site Request Forgery) exploitation attempts
- No SSRF (Server-Side Request Forgery) testing
- No Open Redirect testing
- No Path Traversal / LFI testing
- No SSTI (Server-Side Template Injection) testing
- No XXE (XML External Entity) testing
- No injection of any attack payloads

### Active Testing Mode

Active testing mode enables **active vulnerability testing** by sending potentially dangerous payloads to discover exploitable vulnerabilities.

⚠️ **WARNING**: Active testing sends attack payloads to the target. Only use active mode on systems you own or have explicit written permission to test. Unauthorized testing may be illegal and could trigger security alerts.

#### What Active Testing Does

✅ **All Safe Mode Checks** (passive analysis)

✅ **Cross-Site Scripting (XSS) Testing**
- Reflected XSS detection
- Payload injection in parameters
- Context-aware payload generation
- Verification with multiple payloads

✅ **SQL Injection (SQLi) Testing**
- Error-based SQLi detection
- Boolean-based blind SQLi
- Time-based blind SQLi
- Multiple database fingerprinting

✅ **Cross-Site Request Forgery (CSRF) Testing**
- CSRF token detection
- SameSite cookie validation
- Form protection analysis

✅ **Server-Side Request Forgery (SSRF) Testing**
- Metadata endpoint testing
- Private network probing
- Protocol smuggling detection

✅ **NoSQL Injection (NoSQLi) Testing**
- NoSQL operator injection
- Authentication bypass detection

✅ **Command Injection (CMDi) Testing**
- OS command injection detection
- Command separator testing

✅ **Open Redirect Testing**
- URL redirection validation
- Parameter-based redirect detection

✅ **Path Traversal / LFI Testing**
- Directory traversal detection
- Local file inclusion testing

✅ **Server-Side Template Injection (SSTI) Testing**
- Template expression injection
- Multiple template engine detection

✅ **XML External Entity (XXE) Testing**
- External entity injection
- XML parser exploitation detection

## When to Use Each Mode

### Use Safe Mode When:

1. **Initial Assessment**: First-time scanning of unknown targets
2. **Reconnaissance**: Gathering information before deeper testing
3. **Production Systems**: Scanning live systems without disrupting operations
4. **Compliance Checks**: Verifying security header compliance
5. **Continuous Monitoring**: Automated scans in CI/CD pipelines
6. **No Explicit Permission**: When you don't have written authorization for active testing
7. **Public Systems**: Testing publicly accessible systems you don't own

### Use Active Testing When:

1. **You Own the System**: Testing your own applications
2. **Written Permission**: You have explicit authorization to perform penetration testing
3. **Test Environments**: Dedicated testing/staging environments
4. **Vulnerability Assessment**: Comprehensive security assessment with authorization
5. **Bug Bounty Programs**: Testing within scope of a bug bounty program
6. **Penetration Testing Engagement**: As part of authorized pen test

## Enabling/Disabling Modes

### CLI Commands

**Safe Mode (Default):**
```bash
# Safe mode is the default
wast scan https://example.com

# Explicitly enable safe mode
wast scan https://example.com --safe-mode=true
```

**Active Testing Mode:**
```bash
# Enable active testing
wast scan https://example.com --active

# Or explicitly disable safe mode
wast scan https://example.com --safe-mode=false
```

### MCP Protocol

**Safe Mode (Default):**
```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://example.com"
  }
}
```

**Active Testing Mode:**
```json
{
  "name": "wast_scan",
  "arguments": {
    "target": "https://example.com",
    "active": true
  }
}
```

## Output Differences

### Safe Mode Output

Safe mode reports only on passive findings:

```json
{
  "success": true,
  "command": "scan",
  "message": "Security scan completed (passive checks only)",
  "data": {
    "headers": {
      "findings": [
        {
          "severity": "high",
          "type": "missing_hsts",
          "rule_id": "WAST-HDR-001",
          "cwe": "CWE-693",
          "message": "Missing HTTP Strict Transport Security header"
        }
      ]
    },
    "cookies": {
      "findings": [
        {
          "severity": "medium",
          "type": "insecure_cookie",
          "rule_id": "WAST-COOKIE-001",
          "message": "Cookie 'session' missing Secure flag"
        }
      ]
    }
  }
}
```

### Active Testing Output

Active testing includes both passive and active findings:

```json
{
  "success": true,
  "command": "scan",
  "message": "Security scan completed (active testing enabled)",
  "data": {
    "headers": {
      "findings": [...]
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
          "verified": true
        }
      ]
    },
    "sqli": {
      "findings": [...]
    },
    "csrf": {
      "findings": [...]
    },
    "ssrf": {
      "findings": [...]
    }
  }
}
```

## Finding Verification

When using active testing, you can enable finding verification to reduce false positives:

```bash
wast scan https://example.com --active --verify
```

With verification enabled:
- Each finding is re-tested with multiple payload variants
- Confidence levels are updated based on verification results
- Unverified findings are **excluded** from results

⚠️ **Note**: Verification increases scan time due to additional requests. Use `--verify` only when you need high-confidence results.

## Discovery Mode

Discovery mode combines crawling and scanning to test all discovered attack surfaces:

```bash
wast scan https://example.com --discover --active --depth 3
```

How it works:
1. Crawl the target to discover forms, endpoints, and parameters
2. Scan each discovered attack surface with actual field names
3. Report findings for all discovered locations

**Safe Mode + Discovery:**
```bash
# Crawl and perform passive checks on all discovered endpoints
wast scan https://example.com --discover
```

**Active Testing + Discovery:**
```bash
# Crawl and perform active testing on all discovered endpoints
wast scan https://example.com --discover --active
```

## Legal and Ethical Considerations

### Legal Risks of Unauthorized Testing

⚠️ **WARNING**: Unauthorized active security testing may violate:
- Computer Fraud and Abuse Act (CFAA) in the USA
- Computer Misuse Act in the UK
- Similar laws in other jurisdictions

**Penalties can include:**
- Civil lawsuits
- Criminal charges
- Fines and imprisonment
- Damage to professional reputation

### Always Get Written Authorization

Before enabling active testing, obtain written authorization that includes:

1. **Scope**: Specific systems/URLs authorized for testing
2. **Methods**: Approved testing methods (e.g., "active vulnerability scanning")
3. **Timeline**: When testing is permitted
4. **Contacts**: Emergency contacts during testing
5. **Exclusions**: Systems/actions that are off-limits

### Bug Bounty Programs

When testing under a bug bounty program:
- Read and follow the scope guidelines
- Respect rate limits and testing hours
- Report findings responsibly
- Don't access or modify user data
- Use safe mode outside the defined scope

### Responsible Disclosure

If you discover a vulnerability:
1. Report it privately to the organization
2. Give them reasonable time to fix it (typically 90 days)
3. Don't publicly disclose until patched
4. Don't exploit the vulnerability for personal gain

## Best Practices

### 1. Start with Safe Mode

Always begin with safe mode to:
- Understand the application's security posture
- Identify low-hanging fruit (misconfigurations)
- Avoid triggering security alerts
- Build a baseline before active testing

```bash
# Step 1: Safe mode assessment
wast scan https://example.com --output json > safe-results.json

# Step 2: Review findings before proceeding
cat safe-results.json | jq '.data.headers.findings'

# Step 3: Enable active testing if authorized
wast scan https://example.com --active --output sarif > active-results.sarif
```

### 2. Use Rate Limiting

Avoid overwhelming target systems:

```bash
# Limit to 2 requests per second
wast scan https://example.com --active --rate-limit 2

# Add delay between requests (500ms)
wast scan https://example.com --active --delay 500
```

### 3. Test Outside Business Hours

If authorized, schedule active testing during off-peak hours:
- Reduce impact on production users
- Easier to detect malicious activity vs. legitimate testing
- Less likely to trigger rate limiting

### 4. Monitor for Impact

During active testing:
- Watch application logs for errors
- Monitor application performance
- Be ready to stop testing if issues arise
- Have contact information for the application owner

### 5. Document Everything

Maintain records of:
- Authorization documentation
- Scan timestamps
- Findings discovered
- Actions taken
- Communications with application owners

## Common Questions

### Q: Can I use safe mode on any website?

**A**: Safe mode performs passive analysis, but you should still:
- Have legitimate business reasons for scanning
- Respect robots.txt and rate limits
- Avoid excessive scanning that could impact availability
- Be aware that even passive scanning may be logged

### Q: Will active testing damage the target?

**A**: Active testing is designed to be non-destructive, but:
- It may trigger security alerts and alarms
- It may temporarily impact application performance
- It may create log entries and audit trails
- Some payloads may be stored in databases (e.g., XSS in comments)

### Q: How do I get permission for active testing?

**A**: Options include:
1. Test your own systems (you own them)
2. Request written authorization from system owner
3. Join a bug bounty program with defined scope
4. Engage in a formal penetration testing contract

### Q: What if I accidentally run active testing?

**A**: If you accidentally enable active mode:
1. Stop the scan immediately (Ctrl+C)
2. Contact the system owner proactively
3. Explain what happened and what was tested
4. Provide scan logs if requested
5. Be prepared to assist with any impact assessment

### Q: Can safe mode detect all vulnerabilities?

**A**: No. Safe mode can only detect:
- Configuration issues (missing headers, weak TLS)
- Security misconfigurations
- Information disclosure in responses

Active testing is required to detect:
- Injection vulnerabilities (XSS, SQLi)
- Business logic flaws
- Authorization issues

## Summary

| Aspect | Safe Mode | Active Testing |
|--------|-----------|----------------|
| **Default** | ✅ Yes | ❌ No |
| **Authorization Required** | Recommended | ✅ Required |
| **Passive Analysis** | ✅ Yes | ✅ Yes |
| **Active Testing** | ❌ No | ✅ Yes |
| **Risk of Detection** | Low | High |
| **Legal Risk** | Lower | Higher |
| **Findings** | Configuration issues | All vulnerabilities |
| **Impact on Target** | Minimal | Moderate |
| **Use Case** | Initial assessment | Authorized pen test |

## Related Documentation

- [Getting Started Guide](getting-started.md) - Quick start and basic usage
- [CLI Reference](cli-reference.md) - Complete command reference
- [MCP Integration Guide](mcp-integration.md) - AI agent integration
- [Authentication Guide](authentication.md) - Testing protected applications

## Conclusion

Safe mode is WAST's default behavior to promote responsible security testing. Always obtain proper authorization before enabling active testing, and remember that even passive scanning should be conducted ethically and legally.

**When in doubt, stay in safe mode.**
