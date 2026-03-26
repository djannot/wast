package crawler

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

func TestParseSitemap_StandardSitemap(t *testing.T) {
	sitemapXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>https://example.com/page1</loc>
		<lastmod>2024-01-01</lastmod>
		<changefreq>daily</changefreq>
		<priority>0.8</priority>
	</url>
	<url>
		<loc>https://example.com/page2</loc>
		<lastmod>2024-01-02</lastmod>
	</url>
	<url>
		<loc>https://example.com/page3</loc>
	</url>
</urlset>`

	reader := strings.NewReader(sitemapXML)
	urls := ParseSitemap(reader)

	expected := []string{
		"https://example.com/page1",
		"https://example.com/page2",
		"https://example.com/page3",
	}

	if len(urls) != len(expected) {
		t.Fatalf("Expected %d URLs, got %d", len(expected), len(urls))
	}

	for i, url := range urls {
		if url != expected[i] {
			t.Errorf("Expected URL %d to be %s, got %s", i, expected[i], url)
		}
	}
}

func TestParseSitemap_SitemapIndex(t *testing.T) {
	sitemapIndexXML := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<sitemap>
		<loc>https://example.com/sitemap1.xml</loc>
		<lastmod>2024-01-01</lastmod>
	</sitemap>
	<sitemap>
		<loc>https://example.com/sitemap2.xml</loc>
		<lastmod>2024-01-02</lastmod>
	</sitemap>
	<sitemap>
		<loc>https://example.com/sitemap3.xml</loc>
	</sitemap>
</sitemapindex>`

	reader := strings.NewReader(sitemapIndexXML)
	urls := ParseSitemap(reader)

	expected := []string{
		"https://example.com/sitemap1.xml",
		"https://example.com/sitemap2.xml",
		"https://example.com/sitemap3.xml",
	}

	if len(urls) != len(expected) {
		t.Fatalf("Expected %d sitemap URLs, got %d", len(expected), len(urls))
	}

	for i, url := range urls {
		if url != expected[i] {
			t.Errorf("Expected sitemap URL %d to be %s, got %s", i, expected[i], url)
		}
	}
}

func TestParseSitemap_GzipCompressed(t *testing.T) {
	sitemapXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>https://example.com/compressed1</loc>
	</url>
	<url>
		<loc>https://example.com/compressed2</loc>
	</url>
</urlset>`

	// Compress the XML using gzip
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	_, err := gzWriter.Write([]byte(sitemapXML))
	if err != nil {
		t.Fatalf("Failed to compress sitemap: %v", err)
	}
	gzWriter.Close()

	urls := ParseSitemap(&buf)

	expected := []string{
		"https://example.com/compressed1",
		"https://example.com/compressed2",
	}

	if len(urls) != len(expected) {
		t.Fatalf("Expected %d URLs from gzipped sitemap, got %d", len(expected), len(urls))
	}

	for i, url := range urls {
		if url != expected[i] {
			t.Errorf("Expected URL %d to be %s, got %s", i, expected[i], url)
		}
	}
}

func TestParseSitemap_EmptyContent(t *testing.T) {
	reader := strings.NewReader("")
	urls := ParseSitemap(reader)

	if len(urls) != 0 {
		t.Errorf("Expected 0 URLs from empty content, got %d", len(urls))
	}
}

func TestParseSitemap_InvalidXML(t *testing.T) {
	invalidXML := `<invalid>This is not a valid sitemap</invalid>`
	reader := strings.NewReader(invalidXML)
	urls := ParseSitemap(reader)

	if len(urls) != 0 {
		t.Errorf("Expected 0 URLs from invalid XML, got %d", len(urls))
	}
}

func TestParseSitemap_EmptyURLs(t *testing.T) {
	sitemapXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc></loc>
	</url>
	<url>
		<loc>https://example.com/valid</loc>
	</url>
</urlset>`

	reader := strings.NewReader(sitemapXML)
	urls := ParseSitemap(reader)

	// Should only get the valid URL, empty ones should be skipped
	if len(urls) != 1 {
		t.Fatalf("Expected 1 URL, got %d", len(urls))
	}

	if urls[0] != "https://example.com/valid" {
		t.Errorf("Expected URL to be https://example.com/valid, got %s", urls[0])
	}
}

func TestParseSitemap_MaxURLsLimit(t *testing.T) {
	// Create a sitemap with more URLs than the limit
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)

	// Create MaxSitemapURLs + 100 URLs
	totalURLs := MaxSitemapURLs + 100
	for i := 0; i < totalURLs; i++ {
		sb.WriteString(`<url><loc>https://example.com/page`)
		sb.WriteString(fmt.Sprintf("%d", i))
		sb.WriteString(`</loc></url>`)
	}
	sb.WriteString(`</urlset>`)

	reader := strings.NewReader(sb.String())
	urls := ParseSitemap(reader)

	// Should be limited to MaxSitemapURLs
	if len(urls) != MaxSitemapURLs {
		t.Errorf("Expected %d URLs (max limit), got %d", MaxSitemapURLs, len(urls))
	}
}

func TestParseSitemap_NoNamespace(t *testing.T) {
	// Some sitemaps might not include the xmlns namespace
	sitemapXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset>
	<url>
		<loc>https://example.com/no-namespace</loc>
	</url>
</urlset>`

	reader := strings.NewReader(sitemapXML)
	urls := ParseSitemap(reader)

	if len(urls) != 1 {
		t.Fatalf("Expected 1 URL, got %d", len(urls))
	}

	if urls[0] != "https://example.com/no-namespace" {
		t.Errorf("Expected URL to be https://example.com/no-namespace, got %s", urls[0])
	}
}

func TestParseSitemap_MixedContent(t *testing.T) {
	// Sitemap with various elements including extra whitespace
	sitemapXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>  https://example.com/page1  </loc>
	</url>
	<url>
		<loc>https://example.com/page2</loc>
		<priority>0.5</priority>
	</url>
</urlset>`

	reader := strings.NewReader(sitemapXML)
	urls := ParseSitemap(reader)

	if len(urls) != 2 {
		t.Fatalf("Expected 2 URLs, got %d", len(urls))
	}

	// XML parser should handle whitespace trimming
	expectedURLs := []string{
		"https://example.com/page1",
		"https://example.com/page2",
	}

	for i, url := range urls {
		trimmed := strings.TrimSpace(url)
		if trimmed != expectedURLs[i] {
			t.Errorf("Expected URL %d to be %s, got %s", i, expectedURLs[i], trimmed)
		}
	}
}
