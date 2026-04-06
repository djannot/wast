// Package commands provides CLI command implementations for WAST.
package commands

import (
	"context"
	"time"

	"github.com/djannot/wast/pkg/auth"
	"github.com/djannot/wast/pkg/crawler"
	"github.com/djannot/wast/pkg/output"
	"github.com/djannot/wast/pkg/ratelimit"
	"github.com/djannot/wast/pkg/urlutil"
	"github.com/spf13/cobra"
)

// NewCrawlCmd creates and returns the crawl command.
func NewCrawlCmd(getFormatter func() *output.Formatter, getAuthConfig func() *auth.AuthConfig, getRateLimitConfig func() ratelimit.Config) *cobra.Command {
	var (
		depth              int
		timeout            time.Duration
		userAgent          string
		noRobots           bool
		concurrency        int
		headless           bool
		headlessTimeout    time.Duration
		waitForSelector    string
		headlessPoolSize   int
		headlessDisableImg bool
	)

	cmd := &cobra.Command{
		Use:   "crawl [target]",
		Short: "Web crawling and content discovery",
		Long: `Crawl a target website to discover content and map the application.

The crawl command performs intelligent web crawling to discover:

  - URLs and endpoints within the application
  - Static resources (JS, CSS, images)
  - API endpoints and parameters
  - Forms and input fields
  - Comments and hidden content
  - Directory structure
  - robots.txt and sitemap.xml contents

The crawler respects robots.txt by default but can be configured
to ignore it for authorized security testing.

Rate Limiting:
  Use --rate-limit or --delay to throttle requests and avoid triggering
  rate limits or DoS protection on target systems.

Examples:
  wast crawl https://example.com              # Basic crawl
  wast crawl https://example.com --output json # JSON output
  wast crawl https://example.com --depth 5     # Crawl depth limit
  wast crawl https://example.com --no-robots   # Ignore robots.txt
  wast crawl https://example.com --timeout 60s # Custom timeout
  wast crawl https://example.com --user-agent "MyBot/1.0" # Custom user agent
  wast crawl https://example.com --rate-limit 2 # 2 requests per second
  wast crawl https://example.com --delay 500   # 500ms delay between requests
  wast crawl https://example.com --headless    # Enable headless browser for JS rendering
  wast crawl https://example.com --headless --wait-for-selector "#content" # Wait for element`,
		Run: func(cmd *cobra.Command, args []string) {
			formatter := getFormatter()
			authConfig := getAuthConfig()
			rateLimitConfig := getRateLimitConfig()

			// Check if target is provided
			if len(args) == 0 {
				// Show available features when no target is provided
				result := struct {
					Features []string `json:"features" yaml:"features"`
					Status   string   `json:"status" yaml:"status"`
				}{
					Features: []string{
						"url_discovery",
						"static_resource_mapping",
						"api_endpoint_detection",
						"form_analysis",
						"robots_txt_parsing",
						"internal_external_link_classification",
					},
					Status: "No target provided. Specify a URL to crawl.",
				}
				formatter.Success("crawl", "Crawl command - available features", result)
				return
			}

			target := args[0]

			// Validate and normalize target URL
			validatedURL, err := urlutil.ValidateTargetURL(target)
			if err != nil {
				formatter.Failure("crawl", "Invalid target URL", map[string]interface{}{
					"error": err.Error(),
				})
				return
			}
			target = validatedURL

			// Create crawler with configured options
			opts := []crawler.Option{
				crawler.WithMaxDepth(depth),
				crawler.WithTimeout(timeout),
				crawler.WithUserAgent(userAgent),
				crawler.WithRespectRobots(!noRobots),
				crawler.WithConcurrency(concurrency),
			}

			// Add authentication if configured
			if !authConfig.IsEmpty() {
				opts = append(opts, crawler.WithAuth(authConfig))
			}

			// Add rate limiting if configured
			if rateLimitConfig.IsEnabled() {
				opts = append(opts, crawler.WithRateLimitConfig(rateLimitConfig))
			}

			// Add headless browser configuration if enabled
			if headless {
				headlessConfig := crawler.DefaultHeadlessConfig()
				headlessConfig.Enabled = true
				headlessConfig.Timeout = headlessTimeout
				headlessConfig.WaitForSelector = waitForSelector
				headlessConfig.PoolSize = headlessPoolSize
				headlessConfig.DisableImages = headlessDisableImg
				opts = append(opts, crawler.WithHeadlessConfig(headlessConfig))
			}

			c := crawler.NewCrawler(opts...)

			// Create a signal-aware context so Ctrl+C cancels in-flight requests,
			// then layer a timeout on top of it.
			sigCtx, sigCancel := signalContext()
			defer sigCancel()
			ctx, cancel := context.WithTimeout(sigCtx, timeout*time.Duration(depth+1))
			defer cancel()

			// Perform the crawl
			result := c.Crawl(ctx, target)

			// Determine message based on results
			message := "Web crawl completed successfully"
			if !result.HasResults() {
				if len(result.Errors) > 0 {
					message = "Web crawl completed with errors"
				} else {
					message = "Web crawl completed - no content discovered"
				}
			}

			formatter.Success("crawl", message, result)
		},
	}

	// Add flags
	cmd.Flags().IntVar(&depth, "depth", 3, "Maximum crawl depth (0 for unlimited)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Timeout for HTTP requests")
	cmd.Flags().StringVar(&userAgent, "user-agent", "WAST/1.0 (Web Application Security Testing)", "User agent string for requests")
	cmd.Flags().BoolVar(&noRobots, "no-robots", false, "Ignore robots.txt rules")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent workers for crawling")

	// Headless browser flags
	cmd.Flags().BoolVar(&headless, "headless", false, "Enable headless browser for JavaScript-rendered content")
	cmd.Flags().DurationVar(&headlessTimeout, "headless-timeout", 30*time.Second, "Timeout for headless browser page loads")
	cmd.Flags().StringVar(&waitForSelector, "wait-for-selector", "", "CSS selector to wait for before extracting content (headless mode)")
	cmd.Flags().IntVar(&headlessPoolSize, "headless-pool-size", 2, "Number of browser instances in headless pool")
	cmd.Flags().BoolVar(&headlessDisableImg, "headless-disable-images", true, "Disable image loading in headless mode for performance")

	return cmd
}
