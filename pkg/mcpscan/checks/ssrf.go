package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/djannot/wast/pkg/callback"
)

// ssrfProbe is a URL used to test for Server-Side Request Forgery.
type ssrfProbe struct {
	URL      string
	Target   string
	Evidence []string
}

var ssrfProbes = []ssrfProbe{
	{
		URL:      "http://169.254.169.254/latest/meta-data/",
		Target:   "AWS metadata endpoint",
		Evidence: []string{"ami-id", "instance-id", "iam", "security-credentials", "local-ipv4"},
	},
	{
		URL:      "http://169.254.169.254/metadata/v1/",
		Target:   "DigitalOcean metadata endpoint",
		Evidence: []string{"droplet_id", "hostname", "region", "interfaces"},
	},
	{
		URL:      "http://metadata.google.internal/computeMetadata/v1/",
		Target:   "GCP metadata endpoint",
		Evidence: []string{"project-id", "instance-id", "service-accounts"},
	},
	{
		URL:      "file:///etc/passwd",
		Target:   "local file read (file:// scheme)",
		Evidence: []string{"root:", "nobody:", "daemon:", "/bin/bash", "/bin/sh"},
	},
	{
		URL:      "http://127.0.0.1/",
		Target:   "localhost (internal service probe)",
		Evidence: []string{"<html", "<!doctype", "server:"},
	},
}

// urlParamKeywords lists parameter names that likely accept URL input.
var urlParamKeywords = []string{
	"url", "uri", "href", "link", "endpoint", "target", "destination",
	"address", "host", "remote", "src", "source", "fetch", "resource",
	"webhook", "callback", "redirect",
}

// SSRFOption configures an SSRFChecker.
type SSRFOption func(*SSRFChecker)

// WithCallbackServer configures out-of-band (OOB) blind SSRF detection using
// the provided callback server. The checker generates a unique callback URL per
// probe, sends it as the parameter value, then waits up to timeout for the
// callback server to receive an HTTP request from the target. If a request
// arrives, a blind SSRF finding is reported.
//
// OOB detection is opt-in: callers that do not call WithCallbackServer get the
// existing response-based detection behaviour unchanged.
func WithCallbackServer(srv *callback.Server, timeout time.Duration) SSRFOption {
	return func(c *SSRFChecker) {
		c.callbackServer = srv
		if timeout > 0 {
			c.callbackTimeout = timeout
		}
	}
}

// SSRFChecker probes URL-accepting MCP tool parameters for SSRF.
type SSRFChecker struct {
	callbackServer  *callback.Server
	callbackTimeout time.Duration
}

// NewSSRFChecker creates a new SSRFChecker. Supply SSRFOption values to enable
// optional features such as OOB callback-based blind SSRF detection.
func NewSSRFChecker(opts ...SSRFOption) *SSRFChecker {
	c := &SSRFChecker{callbackTimeout: 5 * time.Second}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Check tests all tools with URL-like parameters for SSRF.
func (c *SSRFChecker) Check(ctx context.Context, tools []ToolInfo, caller ToolCaller) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, c.checkTool(ctx, tool, caller)...)
	}
	return findings
}

func (c *SSRFChecker) checkTool(ctx context.Context, tool ToolInfo, caller ToolCaller) []Finding {
	var findings []Finding
	for _, param := range tool.Parameters {
		if !isURLParameter(param) {
			continue
		}
		findings = append(findings, c.testURLParam(ctx, tool, param, caller)...)
	}
	return findings
}

// isURLParameter returns true if the parameter is likely to accept a URL.
func isURLParameter(param ParamInfo) bool {
	if !strings.EqualFold(param.Type, "string") {
		return false
	}
	lower := strings.ToLower(param.Name + " " + param.Description)
	for _, kw := range urlParamKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (c *SSRFChecker) testURLParam(ctx context.Context, tool ToolInfo, param ParamInfo, caller ToolCaller) []Finding {
	var findings []Finding

	// --- Response-based probes (existing behaviour) ---
	for _, probe := range ssrfProbes {
		args := buildSSRFArgs(tool, param.Name, probe.URL)
		resp, err := caller.CallTool(ctx, tool.Name, args)
		responseText := ""
		if err != nil {
			responseText = strings.ToLower(err.Error())
		} else {
			responseText = strings.ToLower(extractResponseText(resp))
		}

		for _, evidence := range probe.Evidence {
			if strings.Contains(responseText, strings.ToLower(evidence)) {
				findings = append(findings, Finding{
					Tool:      tool.Name,
					Parameter: param.Name,
					Category:  CategorySSRF,
					Severity:  SeverityCritical,
					Title:     fmt.Sprintf("SSRF vulnerability — %s accessible", probe.Target),
					Description: fmt.Sprintf(
						"Tool %q parameter %q is vulnerable to SSRF. "+
							"Sending the URL %q caused the server to contact %s, "+
							"and the response contained %q.",
						tool.Name, param.Name, probe.URL, probe.Target, evidence,
					),
					Evidence:    fmt.Sprintf("Probe URL: %s | Evidence: %s | Response: %s", probe.URL, evidence, truncate(responseText, 200)),
					Remediation: "Implement a strict URL allowlist. Block requests to private IP ranges, link-local, and loopback. Disable file:// scheme.",
				})
				break
			}
		}
	}

	// --- OOB probe for blind SSRF detection (opt-in via WithCallbackServer) ---
	if c.callbackServer != nil {
		if f := c.testOOBProbe(ctx, tool, param, caller); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

// testOOBProbe sends a unique callback URL as the probe value and waits for the
// callback server to receive an HTTP request. Returns a Finding if the callback
// fires within the configured timeout, nil otherwise.
func (c *SSRFChecker) testOOBProbe(ctx context.Context, tool ToolInfo, param ParamInfo, caller ToolCaller) *Finding {
	probeID := c.callbackServer.GenerateCallbackID()
	callbackURL := c.callbackServer.GetHTTPCallbackURL(probeID)
	if callbackURL == "" {
		// Callback server has no base URL configured — skip.
		return nil
	}

	args := buildSSRFArgs(tool, param.Name, callbackURL)

	// Register the callback *before* sending the probe to avoid a race where
	// the server responds faster than we register.
	notifier := make(chan callback.CallbackEvent, 1)
	c.callbackServer.RegisterCallback(probeID, c.callbackTimeout, nil, notifier)
	defer c.callbackServer.UnregisterCallback(probeID)

	// Send the probe. We deliberately ignore the response content — blind SSRF
	// means the server may not echo anything back.
	_, _ = caller.CallTool(ctx, tool.Name, args)

	// Wait for the OOB callback.
	timer := time.NewTimer(c.callbackTimeout)
	defer timer.Stop()

	select {
	case event := <-notifier:
		return &Finding{
			Tool:      tool.Name,
			Parameter: param.Name,
			Category:  CategorySSRF,
			Severity:  SeverityCritical,
			Title:     "Blind SSRF vulnerability — OOB callback received",
			Description: fmt.Sprintf(
				"Tool %q parameter %q is vulnerable to blind SSRF. "+
					"Sending the callback URL %q caused the server to make an outbound "+
					"HTTP request to the callback server (source IP: %s).",
				tool.Name, param.Name, callbackURL, event.SourceIP,
			),
			Evidence:    fmt.Sprintf("Probe URL: %s | Callback source IP: %s | HTTP method: %s", callbackURL, event.SourceIP, event.Method),
			Remediation: "Implement a strict URL allowlist. Block requests to private IP ranges, link-local, and loopback. Disable file:// scheme.",
		}
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return nil
	}
}

// buildSSRFArgs constructs the tool arguments map for an SSRF probe.
// It sets paramName to probeValue and fills required parameters with safe defaults.
func buildSSRFArgs(tool ToolInfo, paramName, probeValue string) map[string]interface{} {
	args := map[string]interface{}{paramName: probeValue}
	for _, p := range tool.Parameters {
		if p.Name == paramName {
			continue
		}
		if p.Required {
			args[p.Name] = defaultValueForType(p.Type)
		}
	}
	return args
}
