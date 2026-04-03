package mcpscan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/djannot/wast/pkg/callback"
	"github.com/djannot/wast/pkg/mcpscan/checks"
)

// ScanConfig holds configuration for an MCP server security scan.
type ScanConfig struct {
	// Transport is the MCP transport: "stdio", "sse", or "http".
	Transport Transport
	// Target is the connection target: command for stdio, URL for sse/http.
	Target string
	// Args are additional arguments for stdio servers.
	Args []string
	// Env are additional environment variables for stdio servers.
	Env []string
	// Timeout is the per-request timeout.
	Timeout time.Duration
	// ActiveMode enables active checks (injection, exposure, SSRF, auth bypass).
	ActiveMode bool
	// SSRFCallbackServer is an optional callback server used for out-of-band
	// blind SSRF detection. When set (and ActiveMode is true) the SSRFChecker
	// will generate a unique callback URL per probe and report a finding if
	// the target server makes an outbound request to that URL.
	//
	// The caller is responsible for starting the server before calling Scan
	// and stopping it afterward.
	SSRFCallbackServer *callback.Server
	// SSRFCallbackTimeout overrides the default OOB callback wait timeout
	// (default 5 s). Only meaningful when SSRFCallbackServer is set.
	SSRFCallbackTimeout time.Duration
}

// Scanner orchestrates MCP server security scanning.
type Scanner struct {
	cfg ScanConfig
}

// NewScanner creates a new Scanner with the given configuration.
func NewScanner(cfg ScanConfig) *Scanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Scanner{cfg: cfg}
}

// Scan runs the full scan workflow: connect → enumerate → check → aggregate.
func (s *Scanner) Scan(ctx context.Context) (*MCPScanResult, error) {
	start := time.Now()

	result := &MCPScanResult{
		ActiveMode: s.cfg.ActiveMode,
		Findings:   []MCPFinding{},
		Summary: MCPScanSummary{
			BySeverity: map[string]int{},
			ByCategory: map[string]int{},
			Errors:     []string{},
		},
	}

	// Build the client for the configured transport.
	client, err := s.buildClient()
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	defer client.Close()

	// Connect and initialize.
	serverInfo, err := client.Connect(ctx)
	if err != nil {
		// Check if authentication is required — produce a finding instead of failing.
		var authErr *ErrAuthRequired
		if errors.As(err, &authErr) {
			result.Server = MCPServerInfo{
				Transport: string(s.cfg.Transport),
				Target:    s.cfg.Target,
			}
			result.Findings = append(result.Findings, MCPFinding{
				Category:    "auth",
				Severity:    "info",
				Title:       "MCP server requires authentication",
				Description: fmt.Sprintf("The MCP server at %q returned HTTP %d. Authentication credentials are required to connect and scan this server. Use --auth-bearer or --auth-header to provide credentials.", s.cfg.Target, authErr.StatusCode),
				Evidence:    authErr.Body,
				Remediation: "Provide valid authentication credentials to scan this server.",
			})
			result.ScanDuration = time.Since(start)
			for _, f := range result.Findings {
				result.Summary.TotalFindings++
				result.Summary.BySeverity[string(f.Severity)]++
				result.Summary.ByCategory[string(f.Category)]++
			}
			return result, nil
		}
		return nil, fmt.Errorf("connect to MCP server: %w", err)
	}
	result.Server = *serverInfo

	// Enumerate tools.
	tools, err := client.ListTools(ctx)
	if err != nil {
		result.Summary.Errors = append(result.Summary.Errors,
			fmt.Sprintf("tools/list failed: %v", err))
	}
	result.Server.Tools = tools
	result.Summary.TotalTools = len(tools)

	// Convert MCPToolInfo to checks.ToolInfo for the checks package.
	checkTools := toCheckTools(tools)

	// Run passive checks.
	var passiveChecksRun int
	passiveFindings := s.runPassiveChecks(checkTools, &passiveChecksRun)
	result.Summary.PassiveChecks = passiveChecksRun

	// Run active checks if enabled.
	var activeFindings []MCPFinding
	if s.cfg.ActiveMode {
		var activeChecksRun int
		activeFindings = s.runActiveChecks(ctx, checkTools, client, &activeChecksRun)
		result.Summary.ActiveChecks = activeChecksRun
	}

	// Aggregate findings.
	allFindings := append(passiveFindings, activeFindings...)
	result.Findings = allFindings

	for _, f := range allFindings {
		result.Summary.TotalFindings++
		result.Summary.BySeverity[string(f.Severity)]++
		result.Summary.ByCategory[string(f.Category)]++
	}

	result.ScanDuration = time.Since(start)

	// Capture how many HTTP 429 retries the client performed across this scan.
	result.Summary.Retries = client.RetryCount()

	return result, nil
}

// buildClient creates the appropriate Client for the configured transport.
func (s *Scanner) buildClient() (*Client, error) {
	opts := []ClientOption{WithTimeout(s.cfg.Timeout)}
	if len(s.cfg.Env) > 0 {
		opts = append(opts, WithEnv(s.cfg.Env))
	}

	switch s.cfg.Transport {
	case TransportStdio:
		return NewStdioClient(s.cfg.Target, s.cfg.Args, opts...), nil
	case TransportSSE:
		return NewSSEClient(s.cfg.Target, opts...), nil
	case TransportHTTP:
		return NewHTTPClient(s.cfg.Target, opts...), nil
	default:
		return nil, fmt.Errorf("unsupported transport: %s", s.cfg.Transport)
	}
}

// runPassiveChecks runs all safe, read-only checks.
// n is incremented for each checker executed.
func (s *Scanner) runPassiveChecks(tools []checks.ToolInfo, n *int) []MCPFinding {
	var findings []MCPFinding

	schemaChecker := checks.NewSchemaChecker()
	findings = append(findings, convertFindings(schemaChecker.Check(tools))...)
	*n++

	promptChecker := checks.NewPromptChecker()
	findings = append(findings, convertFindings(promptChecker.Check(tools))...)
	*n++

	permissionsChecker := checks.NewPermissionsChecker()
	findings = append(findings, convertFindings(permissionsChecker.Check(tools))...)
	*n++

	shadowingChecker := checks.NewShadowingChecker()
	findings = append(findings, convertFindings(shadowingChecker.Check(tools))...)
	*n++

	return findings
}

// runActiveChecks runs checks that invoke tools with potentially harmful payloads.
// n is incremented for each checker executed.
func (s *Scanner) runActiveChecks(ctx context.Context, tools []checks.ToolInfo, client *Client, n *int) []MCPFinding {
	var findings []MCPFinding

	injectionChecker := checks.NewInjectionChecker()
	findings = append(findings, convertFindings(injectionChecker.Check(ctx, tools, client))...)
	*n++

	exposureChecker := checks.NewExposureChecker()
	findings = append(findings, convertFindings(exposureChecker.Check(ctx, tools, client))...)
	*n++

	var ssrfOpts []checks.SSRFOption
	if s.cfg.SSRFCallbackServer != nil {
		ssrfOpts = append(ssrfOpts, checks.WithCallbackServer(s.cfg.SSRFCallbackServer, s.cfg.SSRFCallbackTimeout))
	}
	ssrfChecker := checks.NewSSRFChecker(ssrfOpts...)
	findings = append(findings, convertFindings(ssrfChecker.Check(ctx, tools, client))...)
	*n++

	// Auth checks only apply to HTTP/SSE transports.
	if s.cfg.Transport == TransportHTTP || s.cfg.Transport == TransportSSE {
		authChecker := checks.NewAuthChecker(s.cfg.Target)
		findings = append(findings, convertFindings(authChecker.CheckUnauthenticated(ctx, tools))...)
		*n++
	}

	return findings
}

// toCheckTools converts MCPToolInfo slice to checks.ToolInfo slice.
func toCheckTools(tools []MCPToolInfo) []checks.ToolInfo {
	result := make([]checks.ToolInfo, len(tools))
	for i, t := range tools {
		params := make([]checks.ParamInfo, len(t.Parameters))
		for j, p := range t.Parameters {
			params[j] = checks.ParamInfo{
				Name:        p.Name,
				Type:        p.Type,
				Description: p.Description,
				Required:    p.Required,
				HasEnum:     p.HasEnum,
			}
		}
		result[i] = checks.ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  params,
			RawSchema:   t.RawSchema,
		}
	}
	return result
}

// convertFindings maps checks.Finding to MCPFinding.
func convertFindings(cfs []checks.Finding) []MCPFinding {
	result := make([]MCPFinding, len(cfs))
	for i, f := range cfs {
		result[i] = MCPFinding{
			Tool:        f.Tool,
			Parameter:   f.Parameter,
			Category:    CheckCategory(f.Category),
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			Remediation: f.Remediation,
		}
	}
	return result
}
