package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxAuthBodyBytes caps the response body read in auth check probes.
const maxAuthBodyBytes = 1 << 20 // 1 MiB

// defaultAuthTimeout is the per-request timeout for httpMCPConnector.
const defaultAuthTimeout = 10 * time.Second

// HTTPClientFactory creates a bare HTTP client for auth bypass tests.
// Abstracted to make testing without a live server possible.
type HTTPClientFactory func() *http.Client

// MCPConnector abstracts connecting to an HTTP/SSE MCP server.
// The production implementation uses the mcpscan.Client; tests provide a mock.
type MCPConnector interface {
	// Connect initializes the MCP handshake and returns (name, version, error).
	Connect(ctx context.Context) (name, version string, err error)
	// ListTools returns tool names without auth.
	ListTools(ctx context.Context) ([]string, error)
	// CallTool invokes a tool and returns true if it succeeded without auth.
	CallTool(ctx context.Context, toolName string, args map[string]interface{}) (bool, error)
}

// AuthChecker tests HTTP/SSE MCP servers for authentication bypass vulnerabilities.
type AuthChecker struct {
	// Target is the HTTP/SSE URL of the server.
	Target string
	// Connector is an optional override for tests.
	Connector MCPConnector
}

// NewAuthChecker creates a new AuthChecker for the given target URL.
func NewAuthChecker(target string) *AuthChecker {
	return &AuthChecker{Target: target}
}

// newHTTPMCPConnector creates the production connector with a timeout-guarded client.
func newHTTPMCPConnector(target string) *httpMCPConnector {
	return &httpMCPConnector{
		target: target,
		client: &http.Client{Timeout: defaultAuthTimeout},
	}
}

// CheckUnauthenticated attempts to connect to the MCP server without credentials
// and reports findings if the server does not require authentication.
func (c *AuthChecker) CheckUnauthenticated(ctx context.Context, tools []ToolInfo) []Finding {
	if c.Target == "" && c.Connector == nil {
		return nil
	}

	var findings []Finding

	connector := c.Connector
	if connector == nil {
		connector = newHTTPMCPConnector(c.Target)
	}

	name, version, err := connector.Connect(ctx)
	if err != nil {
		// Server correctly rejected unauthenticated connect.
		return nil
	}

	// Successfully initialized without credentials.
	findings = append(findings, Finding{
		Category: CategoryAuth,
		Severity: SeverityHigh,
		Title:    "MCP server accessible without authentication",
		Description: fmt.Sprintf(
			"The MCP server at %q accepted the initialize handshake without any "+
				"authentication credentials. Any client can enumerate and potentially "+
				"invoke all exposed tools.",
			c.Target,
		),
		Evidence:    fmt.Sprintf("Server responded to initialize: name=%s, version=%s", name, version),
		Remediation: "Require authentication (e.g., Bearer token, mTLS) before allowing clients to call initialize.",
	})

	// Try to list tools unauthenticated.
	toolNames, err := connector.ListTools(ctx)
	if err == nil && len(toolNames) > 0 {
		findings = append(findings, Finding{
			Category: CategoryAuth,
			Severity: SeverityCritical,
			Title:    "Tool enumeration accessible without authentication",
			Description: fmt.Sprintf(
				"The MCP server at %q allows unauthenticated clients to enumerate "+
					"%d tools via tools/list.",
				c.Target, len(toolNames),
			),
			Evidence:    fmt.Sprintf("Tools returned: %s", strings.Join(toolNames, ", ")),
			Remediation: "Authenticate clients before allowing tools/list.",
		})
	}

	// Test per-tool auth bypass.
	for _, tool := range tools {
		args := map[string]interface{}{}
		for _, p := range tool.Parameters {
			if p.Required {
				args[p.Name] = defaultValueForType(p.Type)
			}
		}

		ok, err := connector.CallTool(ctx, tool.Name, args)
		if err == nil && ok {
			findings = append(findings, Finding{
				Tool:     tool.Name,
				Category: CategoryAuth,
				Severity: SeverityHigh,
				Title:    "Tool callable without authentication",
				Description: fmt.Sprintf(
					"Tool %q on the MCP server at %q returned a successful response "+
						"without any authentication credentials being provided.",
					tool.Name, c.Target,
				),
				Remediation: "Implement per-tool authorization checks.",
			})
		}
	}

	return findings
}

// httpMCPConnector is the production MCPConnector that uses real HTTP calls.
// It imports nothing from the parent mcpscan package to avoid circular imports.
type httpMCPConnector struct {
	target string
	// client has an explicit timeout; never use http.DefaultClient.
	client *http.Client
}

func (h *httpMCPConnector) Connect(ctx context.Context) (string, string, error) {
	// Build a minimal initialize request using raw HTTP.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"wast-auth-check","version":"1.0.0"},"capabilities":{}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.target, strings.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", "", fmt.Errorf("HTTP %d: authentication required", resp.StatusCode)
	}

	// Try to extract the server name/version from the initialize response.
	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxAuthBodyBytes))
	if readErr != nil {
		return "unknown", "unknown", nil
	}

	var initResp struct {
		Result struct {
			ServerInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rawBody, &initResp); err != nil {
		return "unknown", "unknown", nil
	}

	name := initResp.Result.ServerInfo.Name
	version := initResp.Result.ServerInfo.Version
	if name == "" {
		name = "unknown"
	}
	if version == "" {
		version = "unknown"
	}
	return name, version, nil
}

func (h *httpMCPConnector) ListTools(ctx context.Context) ([]string, error) {
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.target, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read tools/list response: %w", err)
	}

	// Parse the JSON-RPC tools/list response to get actual tool names.
	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rawBody, &listResp); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}

	names := make([]string, 0, len(listResp.Result.Tools))
	for _, t := range listResp.Result.Tools {
		if t.Name != "" {
			names = append(names, t.Name)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no tools returned by server")
	}
	return names, nil
}

func (h *httpMCPConnector) CallTool(ctx context.Context, toolName string, args map[string]interface{}) (bool, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, toolName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.target, strings.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
