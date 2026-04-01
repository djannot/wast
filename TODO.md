# WAST - TODO

## MCP Server Security Scanning

WAST can now reliably detect web vulnerabilities (XSS, SQLi, CMDi, Path Traversal, CSRF) with zero false positives. Next step: extend into AI security by scanning MCP servers.

### New command: `wast mcpscan`

MCP servers expose tools via JSON-RPC 2.0 over stdio/SSE/HTTP. This is a new attack surface — tool parameters can be injected, descriptions can carry prompt injection, tools can have excessive permissions, and servers may lack authentication.

```
wast mcpscan <transport> <target> [flags]

wast mcpscan stdio -- npx @modelcontextprotocol/server-filesystem /tmp
wast mcpscan sse https://example.com/sse
wast mcpscan http https://example.com/mcp
```

---

### Phase 1: Core infrastructure

- [ ] `pkg/mcpscan/types.go` — Result types: `MCPScanResult`, `MCPFinding`, `MCPToolInfo`, `MCPServerInfo`
- [ ] `pkg/mcpscan/client.go` — MCP client that connects via stdio/SSE/HTTP, sends JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`)
- [ ] `pkg/mcpscan/scanner.go` — Orchestrator: connect, enumerate tools, run checks, aggregate results
- [ ] `internal/commands/mcpscan.go` — CLI command with transport subcommands and flags
- [ ] `cmd/wast/root.go` — Register `NewMCPScanCmd`
- [ ] `internal/mcp/server.go` — Register `wast_mcpscan` tool
- [ ] `internal/mcp/execute.go` — Add `executeMCPScan()` function

### Phase 2: MCP server discovery

Before scanning, you need to find MCP servers. Discovery methods:

- [ ] **Local config discovery** — Parse known MCP config files to find configured servers:
  - Claude Desktop: `~/.claude/claude_desktop_config.json`
  - Claude Code: `~/.claude.json`, `.mcp.json`, project-level `CLAUDE.md`
  - Cursor: `~/.cursor/mcp.json`
  - VS Code (Copilot): `.vscode/mcp.json`
  - Cline: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
  - Windsurf: `~/.codeium/windsurf/mcp_config.json`
- [ ] **Network discovery** — Scan for HTTP/SSE MCP endpoints:
  - Probe common MCP paths on a target: `/.well-known/mcp`, `/mcp`, `/sse`, `/api/mcp`
  - Check response for JSON-RPC 2.0 handshake indicators
- [x] **NPM/PyPI registry scanning** — Given a project, identify MCP server dependencies in `package.json`/`requirements.txt` and flag known-vulnerable versions
- [ ] Wire discovery into both CLI (`wast mcpscan discover`) and MCP tool (`wast_mcpscan` with `discover` mode)

### Phase 3: Passive checks (safe mode, no tool invocation)

- [ ] **Schema analysis** (`checks/schema.go`) — Enumerate tools via `tools/list`. Flag missing input validation (`required`, `enum`), overly permissive string params, undocumented parameters
- [ ] **Prompt injection detection** (`checks/prompt.go`) — Analyze tool/param descriptions for AI-directed instructions ("ignore previous", "you must"), hidden Unicode (zero-width chars), encoded payloads (base64), excessive length
- [ ] **Permission auditing** (`checks/permissions.go`) — Flag dangerous capabilities: file system access, shell execution, network requests, database queries. Score by scope breadth (any file vs scoped directory)
- [ ] **Tool shadowing** (`checks/shadowing.go`) — Detect name collisions across multiple servers, typosquatting variants (`read_flie` vs `read_file`)

### Phase 4: Active checks (requires `--active`)

- [ ] **Tool parameter injection** (`checks/injection.go`) — Send SQLi, CMDi, path traversal payloads through tool string params. Analyze responses for injection evidence
- [ ] **Data exposure** (`checks/exposure.go`) — Invoke tools with benign args, scan responses for leaked credentials, PII, internal paths, stack traces, environment variables
- [ ] **SSRF via tools** (`checks/ssrf.go`) — Identify URL-accepting parameters, send internal network probes (`http://169.254.169.254/`, `file:///etc/passwd`)
- [ ] **Auth bypass** (`checks/auth.go`) — For HTTP/SSE: test unauthenticated access. Test per-tool authorization (can any client call any tool?)

### Phase 5: Tests and benchmarks

- [x] Unit tests for MCP client (mock stdio server)
- [x] Unit tests for each check
- [x] Create a deliberately vulnerable MCP server for integration testing (`test/integration/mcpscan/vulnerable_server/main.go`)
- [x] CI integration with `make test-mcpscan`
- [x] Hard assertions: each check must detect its target vulnerability on the test server (`test/integration/mcpscan/mcpscan_test.go`)

### Package structure

```
pkg/mcpscan/
  client.go           # MCP client: stdio/SSE/HTTP transports
  types.go            # Result types
  scanner.go          # Orchestrator
  discovery.go        # Find MCP servers (local configs, network probes)
  checks/
    schema.go         # Tool enumeration and schema analysis
    prompt.go         # Prompt injection in descriptions
    permissions.go    # Capability auditing
    shadowing.go      # Tool name collisions
    injection.go      # Parameter injection testing
    exposure.go       # Data exposure analysis
    ssrf.go           # SSRF via tool parameters
    auth.go           # Auth bypass testing
```
