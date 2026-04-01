package checks

import (
	"context"
	"fmt"
	"strings"
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

// SSRFChecker probes URL-accepting MCP tool parameters for SSRF.
type SSRFChecker struct{}

// NewSSRFChecker creates a new SSRFChecker.
func NewSSRFChecker() *SSRFChecker {
	return &SSRFChecker{}
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

	for _, probe := range ssrfProbes {
		args := map[string]interface{}{param.Name: probe.URL}
		for _, p := range tool.Parameters {
			if p.Name == param.Name {
				continue
			}
			if p.Required {
				args[p.Name] = defaultValueForType(p.Type)
			}
		}

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

	return findings
}
