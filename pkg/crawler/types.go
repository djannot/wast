// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"fmt"
	"strings"
)

// LinkInfo represents a discovered link/URL.
type LinkInfo struct {
	URL      string `json:"url" yaml:"url"`
	Text     string `json:"text,omitempty" yaml:"text,omitempty"`
	Rel      string `json:"rel,omitempty" yaml:"rel,omitempty"`
	External bool   `json:"external" yaml:"external"`
	Depth    int    `json:"depth" yaml:"depth"`
}

// FormInfo represents a discovered HTML form.
type FormInfo struct {
	Action string          `json:"action" yaml:"action"`
	Method string          `json:"method" yaml:"method"`
	Fields []FormFieldInfo `json:"fields,omitempty" yaml:"fields,omitempty"`
	Page   string          `json:"page" yaml:"page"`
}

// FormFieldInfo represents a form input field.
type FormFieldInfo struct {
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type" yaml:"type"`
	Value    string `json:"value,omitempty" yaml:"value,omitempty"`
	Required bool   `json:"required" yaml:"required"`
}

// ResourceInfo represents a discovered static resource (JS, CSS, images).
type ResourceInfo struct {
	URL  string `json:"url" yaml:"url"`
	Type string `json:"type" yaml:"type"`
	Page string `json:"page" yaml:"page"`
}

// CrawlResult contains the results of a web crawl operation.
type CrawlResult struct {
	Target         string         `json:"target" yaml:"target"`
	CrawledURLs    []string       `json:"crawled_urls,omitempty" yaml:"crawled_urls,omitempty"`
	InternalLinks  []LinkInfo     `json:"internal_links,omitempty" yaml:"internal_links,omitempty"`
	ExternalLinks  []LinkInfo     `json:"external_links,omitempty" yaml:"external_links,omitempty"`
	Forms          []FormInfo     `json:"forms,omitempty" yaml:"forms,omitempty"`
	Resources      []ResourceInfo `json:"resources,omitempty" yaml:"resources,omitempty"`
	RobotsDisallow []string       `json:"robots_disallow,omitempty" yaml:"robots_disallow,omitempty"`
	Errors         []string       `json:"errors,omitempty" yaml:"errors,omitempty"`
	Statistics     CrawlStats     `json:"statistics" yaml:"statistics"`
}

// CrawlStats contains statistics about the crawl operation.
type CrawlStats struct {
	TotalURLs       int `json:"total_urls" yaml:"total_urls"`
	InternalURLs    int `json:"internal_urls" yaml:"internal_urls"`
	ExternalURLs    int `json:"external_urls" yaml:"external_urls"`
	FormsFound      int `json:"forms_found" yaml:"forms_found"`
	ResourcesFound  int `json:"resources_found" yaml:"resources_found"`
	MaxDepthReached int `json:"max_depth_reached" yaml:"max_depth_reached"`
}

// String returns a human-readable representation of the crawl result.
func (r *CrawlResult) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Web Crawl Results for: %s\n", r.Target))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	sb.WriteString(fmt.Sprintf("\nStatistics:\n"))
	sb.WriteString(fmt.Sprintf("  Total URLs: %d\n", r.Statistics.TotalURLs))
	sb.WriteString(fmt.Sprintf("  Internal URLs: %d\n", r.Statistics.InternalURLs))
	sb.WriteString(fmt.Sprintf("  External URLs: %d\n", r.Statistics.ExternalURLs))
	sb.WriteString(fmt.Sprintf("  Forms Found: %d\n", r.Statistics.FormsFound))
	sb.WriteString(fmt.Sprintf("  Resources Found: %d\n", r.Statistics.ResourcesFound))
	sb.WriteString(fmt.Sprintf("  Max Depth Reached: %d\n", r.Statistics.MaxDepthReached))

	if len(r.CrawledURLs) > 0 {
		sb.WriteString("\nCrawled URLs:\n")
		for _, url := range r.CrawledURLs {
			sb.WriteString(fmt.Sprintf("  - %s\n", url))
		}
	}

	if len(r.InternalLinks) > 0 {
		sb.WriteString("\nInternal Links:\n")
		for _, link := range r.InternalLinks {
			sb.WriteString(fmt.Sprintf("  - %s (depth: %d)\n", link.URL, link.Depth))
		}
	}

	if len(r.ExternalLinks) > 0 {
		sb.WriteString("\nExternal Links:\n")
		for _, link := range r.ExternalLinks {
			sb.WriteString(fmt.Sprintf("  - %s\n", link.URL))
		}
	}

	if len(r.Forms) > 0 {
		sb.WriteString("\nForms Found:\n")
		for _, form := range r.Forms {
			sb.WriteString(fmt.Sprintf("  - Action: %s, Method: %s, Fields: %d\n",
				form.Action, form.Method, len(form.Fields)))
		}
	}

	if len(r.Resources) > 0 {
		sb.WriteString("\nStatic Resources:\n")
		for _, res := range r.Resources {
			sb.WriteString(fmt.Sprintf("  - [%s] %s\n", res.Type, res.URL))
		}
	}

	if len(r.RobotsDisallow) > 0 {
		sb.WriteString("\nRobots.txt Disallowed Paths:\n")
		for _, path := range r.RobotsDisallow {
			sb.WriteString(fmt.Sprintf("  - %s\n", path))
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors encountered:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	return sb.String()
}

// HasResults returns true if any results were found.
func (r *CrawlResult) HasResults() bool {
	return len(r.CrawledURLs) > 0 || len(r.InternalLinks) > 0 ||
		len(r.ExternalLinks) > 0 || len(r.Forms) > 0 || len(r.Resources) > 0
}
