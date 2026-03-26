package crawler

import (
	"net/url"
	"strings"
	"testing"
)

// TestParseRobots tests the ParseRobots function with various inputs
func TestParseRobots(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		wantDisallow []string
		wantAllow    []string
		wantSitemaps []string
	}{
		{
			name:         "empty input",
			content:      "",
			wantDisallow: []string{},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "comments only",
			content: `# This is a comment
# Another comment
# Yet another comment`,
			wantDisallow: []string{},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "basic robots.txt",
			content: `User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public
Sitemap: https://example.com/sitemap.xml`,
			wantDisallow: []string{"/admin", "/private/"},
			wantAllow:    []string{"/public"},
			wantSitemaps: []string{"https://example.com/sitemap.xml"},
		},
		{
			name: "with comments",
			content: `# This is a robots.txt file
User-agent: *
# Disallow admin
Disallow: /admin`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "malformed lines - missing colons",
			content: `User-agent: *
Disallow /admin
Allow /public
Disallow: /private`,
			wantDisallow: []string{"/private"},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "extra whitespace",
			content: `User-agent:   *
Disallow:    /admin
Allow:      /public
Sitemap:     https://example.com/sitemap.xml`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{"/public"},
			wantSitemaps: []string{"https://example.com/sitemap.xml"},
		},
		{
			name: "multiple user-agent blocks",
			content: `User-agent: Googlebot
Disallow: /google-admin

User-agent: *
Disallow: /admin
Allow: /public

User-agent: Bingbot
Disallow: /bing-admin`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{"/public"},
			wantSitemaps: []string{},
		},
		{
			name: "crawl-delay directive (currently ignored)",
			content: `User-agent: *
Crawl-delay: 10
Disallow: /admin`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "empty disallow (allows all)",
			content: `User-agent: *
Disallow:`,
			wantDisallow: []string{},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "empty allow",
			content: `User-agent: *
Allow:
Disallow: /admin`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "multiple sitemaps",
			content: `User-agent: *
Sitemap: https://example.com/sitemap1.xml
Sitemap: https://example.com/sitemap2.xml
Sitemap: https://example.com/sitemap-index.xml`,
			wantDisallow: []string{},
			wantAllow:    []string{},
			wantSitemaps: []string{
				"https://example.com/sitemap1.xml",
				"https://example.com/sitemap2.xml",
				"https://example.com/sitemap-index.xml",
			},
		},
		{
			name: "wildcard patterns",
			content: `User-agent: *
Disallow: /*.php
Disallow: /admin/*/secret
Allow: *.jpg$`,
			wantDisallow: []string{"/*.php", "/admin/*/secret"},
			wantAllow:    []string{"*.jpg$"},
			wantSitemaps: []string{},
		},
		{
			name: "empty user-agent treated as wildcard",
			content: `User-agent:
Disallow: /test`,
			wantDisallow: []string{"/test"},
			wantAllow:    []string{},
			wantSitemaps: []string{},
		},
		{
			name: "case insensitive directives",
			content: `USER-AGENT: *
DISALLOW: /admin
ALLOW: /public
SITEMAP: https://example.com/sitemap.xml`,
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{"/public"},
			wantSitemaps: []string{"https://example.com/sitemap.xml"},
		},
		{
			name: "mixed line endings and whitespace",
			content: "User-agent: *\r\nDisallow: /admin\r\n\nAllow: /public\n\r\nSitemap: https://example.com/sitemap.xml",
			wantDisallow: []string{"/admin"},
			wantAllow:    []string{"/public"},
			wantSitemaps: []string{"https://example.com/sitemap.xml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := ParseRobots(strings.NewReader(tt.content))

			if len(data.Disallow) != len(tt.wantDisallow) {
				t.Errorf("Disallow count: got %d, want %d", len(data.Disallow), len(tt.wantDisallow))
			} else {
				for i, v := range data.Disallow {
					if v != tt.wantDisallow[i] {
						t.Errorf("Disallow[%d]: got %q, want %q", i, v, tt.wantDisallow[i])
					}
				}
			}

			if len(data.Allow) != len(tt.wantAllow) {
				t.Errorf("Allow count: got %d, want %d", len(data.Allow), len(tt.wantAllow))
			} else {
				for i, v := range data.Allow {
					if v != tt.wantAllow[i] {
						t.Errorf("Allow[%d]: got %q, want %q", i, v, tt.wantAllow[i])
					}
				}
			}

			if len(data.Sitemaps) != len(tt.wantSitemaps) {
				t.Errorf("Sitemaps count: got %d, want %d", len(data.Sitemaps), len(tt.wantSitemaps))
			} else {
				for i, v := range data.Sitemaps {
					if v != tt.wantSitemaps[i] {
						t.Errorf("Sitemaps[%d]: got %q, want %q", i, v, tt.wantSitemaps[i])
					}
				}
			}
		})
	}
}

// TestRobotsData_IsAllowed tests the IsAllowed method with various scenarios
func TestRobotsData_IsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		robots   *RobotsData
		path     string
		expected bool
	}{
		{
			name:     "no rules - allowed",
			robots:   &RobotsData{},
			path:     "/anything",
			expected: true,
		},
		{
			name:     "empty path - normalized to /",
			robots:   &RobotsData{Disallow: []string{"/"}},
			path:     "",
			expected: false,
		},
		{
			name:     "root path - allowed",
			robots:   &RobotsData{},
			path:     "/",
			expected: true,
		},
		{
			name: "root path - disallowed",
			robots: &RobotsData{
				Disallow: []string{"/"},
			},
			path:     "/",
			expected: false,
		},
		{
			name: "disallowed path",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/admin",
			expected: false,
		},
		{
			name: "disallowed prefix",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/admin/users",
			expected: false,
		},
		{
			name: "allowed path",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/public",
			expected: true,
		},
		{
			name: "allow overrides disallow",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
				Allow:    []string{"/admin/public"},
			},
			path:     "/admin/public",
			expected: true,
		},
		{
			name: "multiple wildcards in pattern",
			robots: &RobotsData{
				Disallow: []string{"/*.php*"},
			},
			path:     "/index.php?page=1",
			expected: false,
		},
		{
			name: "wildcard at start",
			robots: &RobotsData{
				Disallow: []string{"*.pdf"},
			},
			path:     "/docs/manual.pdf",
			expected: false,
		},
		{
			name: "end anchor with wildcard",
			robots: &RobotsData{
				Disallow: []string{"/*.gif$"},
			},
			path:     "/image.gif",
			expected: false,
		},
		{
			name: "end anchor - path has suffix",
			robots: &RobotsData{
				Disallow: []string{"/*.gif$"},
			},
			path:     "/image.gif.bak",
			expected: true,
		},
		{
			name: "case sensitivity - different case",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
			},
			path:     "/Admin",
			expected: true, // robots.txt is case-sensitive
		},
		{
			name: "case sensitivity - exact case",
			robots: &RobotsData{
				Disallow: []string{"/Admin"},
			},
			path:     "/Admin",
			expected: false,
		},
		{
			name: "url-encoded path - space",
			robots: &RobotsData{
				Disallow: []string{"/path%20with%20spaces"},
			},
			path:     "/path%20with%20spaces",
			expected: false,
		},
		{
			name: "url-encoded path - not matching",
			robots: &RobotsData{
				Disallow: []string{"/path with spaces"},
			},
			path:     "/path%20with%20spaces",
			expected: true, // literal matching
		},
		{
			name: "complex wildcard pattern",
			robots: &RobotsData{
				Disallow: []string{"/admin/*/edit.*"},
			},
			path:     "/admin/users/edit.php",
			expected: false,
		},
		{
			name: "consecutive wildcards",
			robots: &RobotsData{
				Disallow: []string{"/**/*"},
			},
			path:     "/path/to/file",
			expected: false,
		},
		{
			name: "wildcard at end",
			robots: &RobotsData{
				Disallow: []string{"/private/*"},
			},
			path:     "/private/secret/data.txt",
			expected: false,
		},
		{
			name: "wildcard in middle",
			robots: &RobotsData{
				Disallow: []string{"/api/*/secret"},
			},
			path:     "/api/v1/secret",
			expected: false,
		},
		{
			name: "allow precedence over longer disallow",
			robots: &RobotsData{
				Disallow: []string{"/admin"},
				Allow:    []string{"/admin/public/docs"},
			},
			path:     "/admin/public/docs/readme.txt",
			expected: true,
		},
		{
			name: "disallow when allow doesn't match",
			robots: &RobotsData{
				Disallow: []string{"/private/*"},
				Allow:    []string{"/private/public/*"},
			},
			path:     "/private/secret/data.txt",
			expected: false,
		},
		{
			name: "end anchor - exact match required",
			robots: &RobotsData{
				Disallow: []string{"/checkout$"},
			},
			path:     "/checkout",
			expected: false,
		},
		{
			name: "end anchor - no match with suffix",
			robots: &RobotsData{
				Disallow: []string{"/checkout$"},
			},
			path:     "/checkout/success",
			expected: true,
		},
		{
			name: "multiple wildcards in single pattern",
			robots: &RobotsData{
				Disallow: []string{"/api/*/v*/users"},
			},
			path:     "/api/public/v1/users",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.robots.IsAllowed(tt.path); got != tt.expected {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// TestMatchWildcard tests the matchWildcard function with complex patterns
func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		pattern  string
		expected bool
	}{
		// Wildcard at start
		{name: "wildcard at start - match", s: "/readme.txt", pattern: "*.txt", expected: true},
		{name: "wildcard at start - no match", s: "/readme.pdf", pattern: "*.txt", expected: false},
		{name: "wildcard at start - match nested", s: "/docs/readme.txt", pattern: "*.txt", expected: true},

		// Wildcard at end
		{name: "wildcard at end - match", s: "/images/logo.png", pattern: "/images/*", expected: true},
		{name: "wildcard at end - match empty suffix", s: "/images/", pattern: "/images/*", expected: true},
		{name: "wildcard at end - match exact prefix", s: "/images", pattern: "/images*", expected: true},
		{name: "wildcard at end - no match", s: "/docs/file.txt", pattern: "/images/*", expected: false},

		// Wildcard in middle
		{name: "wildcard in middle - match", s: "/path/foo/file", pattern: "/path/*/file", expected: true},
		{name: "wildcard in middle - no match", s: "/path/foo/other", pattern: "/path/*/file", expected: false},
		{name: "wildcard in middle - match nested", s: "/path/foo/bar/file", pattern: "/path/*/file", expected: true},

		// Multiple wildcards
		{name: "multiple wildcards - match", s: "/a/b/c", pattern: "*/*", expected: true},
		{name: "multiple wildcards - match complex", s: "/images/2023/photo.jpg", pattern: "/images/*/photo.*", expected: true},
		{name: "multiple wildcards - no match", s: "/images/2023/document.pdf", pattern: "/images/*/photo.*", expected: false},

		// End anchor with wildcard
		{name: "wildcard with end anchor - match", s: "/image.gif", pattern: "/*.gif$", expected: true},
		{name: "wildcard with end anchor - no match suffix", s: "/image.gif.bak", pattern: "/*.gif$", expected: false},
		{name: "wildcard with end anchor - match in subdir", s: "/images/logo.gif", pattern: "/*.gif$", expected: true},
		{name: "wildcard with end anchor - no match different ext", s: "/image.png", pattern: "/*.gif$", expected: false},

		// No wildcard (edge case)
		{name: "no wildcard - prefix match", s: "/admin/users", pattern: "/admin", expected: true},
		{name: "no wildcard - exact match", s: "/admin", pattern: "/admin", expected: true},

		// Empty pattern edge cases
		{name: "empty pattern - empty string", s: "", pattern: "", expected: true},
		{name: "empty pattern - non-empty string", s: "/path", pattern: "", expected: true},

		// Only wildcard
		{name: "only wildcard - match any", s: "/anything/here", pattern: "*", expected: true},
		{name: "only wildcard - match empty", s: "", pattern: "*", expected: true},

		// Consecutive wildcards
		{name: "consecutive wildcards - match", s: "/a/b/c", pattern: "**", expected: true},
		{name: "consecutive wildcards in middle", s: "/path/to/file", pattern: "/path**/file", expected: true},

		// Complex patterns
		{name: "complex pattern - match", s: "/admin/user/edit.php", pattern: "/admin/*/edit.*", expected: true},
		{name: "complex pattern - no match", s: "/admin/user/view.php", pattern: "/admin/*/edit.*", expected: false},
		{name: "pattern with end anchor - match", s: "/page.html", pattern: "*.html$", expected: true},
		{name: "pattern with end anchor - no match", s: "/page.html.bak", pattern: "*.html$", expected: false},

		// Multiple wildcards edge cases
		{name: "three wildcards", s: "/a/b/c/d.txt", pattern: "*/*/*/*.txt", expected: true},
		{name: "wildcard only at start and end", s: "/middle/part/file", pattern: "*part*", expected: true},

		// Empty parts between wildcards
		{name: "consecutive wildcards - empty parts", s: "/path/file", pattern: "/**", expected: true},
		{name: "wildcards with empty segments", s: "/a/b", pattern: "*/*", expected: true},

		// Complex end anchor patterns
		{name: "complex end anchor - match", s: "/static/2023/style.css", pattern: "/static/*/*.css$", expected: true},
		{name: "complex end anchor - no match suffix", s: "/static/2023/style.css.map", pattern: "/static/*/*.css$", expected: false},

		// Edge cases with special characters
		{name: "pattern with query string", s: "/page.php?id=1", pattern: "*.php*", expected: true},
		{name: "pattern with query string - end anchor", s: "/page.php?id=1", pattern: "*.php$", expected: false},

		// Prefix matching without wildcards
		{name: "prefix only - match", s: "/admin/panel", pattern: "/admin", expected: true},
		{name: "prefix only - no match", s: "/user/admin", pattern: "/admin", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchWildcard(tt.s, tt.pattern); got != tt.expected {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tt.s, tt.pattern, got, tt.expected)
			}
		})
	}
}

// TestMatchesRobotsPath tests the matchesRobotsPath function
func TestMatchesRobotsPath(t *testing.T) {
	tests := []struct {
		name       string
		urlPath    string
		robotsPath string
		expected   bool
	}{
		// End anchor tests
		{name: "end anchor - exact match", urlPath: "/page", robotsPath: "/page$", expected: true},
		{name: "end anchor - no match with suffix", urlPath: "/page123", robotsPath: "/page$", expected: false},
		{name: "end anchor - no match with extension", urlPath: "/page.html", robotsPath: "/page$", expected: false},
		{name: "end anchor - match root", urlPath: "/", robotsPath: "/$", expected: true},
		{name: "end anchor - no match prefix", urlPath: "/homepage", robotsPath: "/page$", expected: false},

		// Wildcard patterns delegating to matchWildcard
		{name: "wildcard pattern - match", urlPath: "/images/logo.png", robotsPath: "/images/*", expected: true},
		{name: "wildcard pattern - no match", urlPath: "/docs/readme.txt", robotsPath: "/images/*", expected: false},
		{name: "wildcard at start - match", urlPath: "/file.pdf", robotsPath: "*.pdf", expected: true},
		{name: "wildcard in middle - match", urlPath: "/api/v1/users", robotsPath: "/api/*/users", expected: true},

		// Combined wildcard and end anchor
		{name: "wildcard with end anchor - match", urlPath: "/image.gif", robotsPath: "/*.gif$", expected: true},
		{name: "wildcard with end anchor - no match", urlPath: "/image.gif.bak", robotsPath: "/*.gif$", expected: false},
		{name: "complex wildcard end anchor - match", urlPath: "/static/2023/style.css", robotsPath: "/static/*/*.css$", expected: true},

		// Simple prefix matching (no special characters)
		{name: "simple prefix - match", urlPath: "/admin/users", robotsPath: "/admin", expected: true},
		{name: "simple prefix - no match", urlPath: "/public", robotsPath: "/admin", expected: false},
		{name: "simple prefix - exact match", urlPath: "/admin", robotsPath: "/admin", expected: true},
		{name: "simple prefix - match nested", urlPath: "/admin/panel/settings", robotsPath: "/admin", expected: true},

		// Edge cases
		{name: "empty robotsPath", urlPath: "/anything", robotsPath: "", expected: true},
		{name: "empty urlPath - prefix match", urlPath: "", robotsPath: "/", expected: false},
		{name: "root path - match", urlPath: "/", robotsPath: "/", expected: true},
		{name: "case sensitive - no match", urlPath: "/Admin", robotsPath: "/admin", expected: false},
		{name: "case sensitive - match", urlPath: "/admin", robotsPath: "/admin", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesRobotsPath(tt.urlPath, tt.robotsPath); got != tt.expected {
				t.Errorf("matchesRobotsPath(%q, %q) = %v, want %v", tt.urlPath, tt.robotsPath, got, tt.expected)
			}
		})
	}
}

// TestGetRobotsURL tests the GetRobotsURL function
func TestGetRobotsURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "basic URL",
			input:   "https://example.com",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with path",
			input:   "https://example.com/page",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with port",
			input:   "http://example.com:8080",
			want:    "http://example.com:8080/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with trailing slash",
			input:   "https://example.com/",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with deep path",
			input:   "https://example.com/path/to/page",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with query string",
			input:   "https://example.com/page?id=1",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with fragment",
			input:   "https://example.com/page#section",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "http URL",
			input:   "http://example.com",
			want:    "http://example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "subdomain",
			input:   "https://subdomain.example.com",
			want:    "https://subdomain.example.com/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with port and path",
			input:   "http://example.com:8080/admin/login",
			want:    "http://example.com:8080/robots.txt",
			wantErr: false,
		},
		{
			name:    "invalid URL - missing scheme",
			input:   "://invalid-url",
			want:    "",
			wantErr: true,
		},
		{
			name:    "relative URL - treated as path",
			input:   "not a url at all",
			want:    "/robots.txt",
			wantErr: false,
		},
		{
			name:    "URL with authentication",
			input:   "https://user:pass@example.com/page",
			want:    "https://example.com/robots.txt",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRobotsURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRobotsURL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("GetRobotsURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestGetRobotsURL_URLComponents verifies URL components are correctly parsed
func TestGetRobotsURL_URLComponents(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantScheme string
		wantHost   string
		wantPath   string
	}{
		{
			name:       "https with port",
			input:      "https://example.com:443/path",
			wantScheme: "https",
			wantHost:   "example.com:443",
			wantPath:   "/robots.txt",
		},
		{
			name:       "http default port",
			input:      "http://example.com/",
			wantScheme: "http",
			wantHost:   "example.com",
			wantPath:   "/robots.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRobotsURL(tt.input)
			if err != nil {
				t.Fatalf("GetRobotsURL(%q) unexpected error: %v", tt.input, err)
			}

			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatalf("Failed to parse result URL: %v", err)
			}

			if parsed.Scheme != tt.wantScheme {
				t.Errorf("Scheme: got %q, want %q", parsed.Scheme, tt.wantScheme)
			}
			if parsed.Host != tt.wantHost {
				t.Errorf("Host: got %q, want %q", parsed.Host, tt.wantHost)
			}
			if parsed.Path != tt.wantPath {
				t.Errorf("Path: got %q, want %q", parsed.Path, tt.wantPath)
			}
		})
	}
}

// TestRobotsData_IsAllowed_Precedence tests the precedence of Allow over Disallow
func TestRobotsData_IsAllowed_Precedence(t *testing.T) {
	tests := []struct {
		name     string
		disallow []string
		allow    []string
		path     string
		expected bool
	}{
		{
			name:     "allow takes precedence - exact match",
			disallow: []string{"/admin"},
			allow:    []string{"/admin/public"},
			path:     "/admin/public",
			expected: true,
		},
		{
			name:     "allow takes precedence - longer path",
			disallow: []string{"/admin"},
			allow:    []string{"/admin/public"},
			path:     "/admin/public/docs",
			expected: true,
		},
		{
			name:     "disallow when allow doesn't match",
			disallow: []string{"/admin"},
			allow:    []string{"/admin/public"},
			path:     "/admin/private",
			expected: false,
		},
		{
			name:     "multiple allows - first match wins",
			disallow: []string{"/private"},
			allow:    []string{"/private/public", "/private/docs"},
			path:     "/private/public/file.txt",
			expected: true,
		},
		{
			name:     "allow with wildcard overrides disallow",
			disallow: []string{"/images/*"},
			allow:    []string{"*.png"},
			path:     "/images/logo.png",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			robots := &RobotsData{
				Disallow: tt.disallow,
				Allow:    tt.allow,
			}
			if got := robots.IsAllowed(tt.path); got != tt.expected {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// TestRobotsData_ParseRobots_EmptyValues tests handling of empty directive values
func TestRobotsData_ParseRobots_EmptyValues(t *testing.T) {
	content := `User-agent: *
Disallow:
Allow:
Disallow: /admin
Allow: /public`

	data := ParseRobots(strings.NewReader(content))

	// Empty Disallow and Allow should be skipped
	if len(data.Disallow) != 1 || data.Disallow[0] != "/admin" {
		t.Errorf("Expected only /admin in Disallow, got %v", data.Disallow)
	}
	if len(data.Allow) != 1 || data.Allow[0] != "/public" {
		t.Errorf("Expected only /public in Allow, got %v", data.Allow)
	}
}
