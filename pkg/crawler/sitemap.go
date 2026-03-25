// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"compress/gzip"
	"encoding/xml"
	"io"
	"strings"
)

// Sitemap XML structures for parsing standard sitemaps and sitemap indexes

// URLSet represents a standard sitemap <urlset> structure
type URLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []URL    `xml:"url"`
}

// URL represents a single URL entry in a sitemap
type URL struct {
	Loc string `xml:"loc"`
}

// SitemapIndex represents a sitemap index file
type SitemapIndex struct {
	XMLName  xml.Name  `xml:"sitemapindex"`
	Sitemaps []Sitemap `xml:"sitemap"`
}

// Sitemap represents a single sitemap reference in a sitemap index
type Sitemap struct {
	Loc string `xml:"loc"`
}

const (
	// MaxSitemapURLs limits the number of URLs parsed from a single sitemap to prevent DoS
	MaxSitemapURLs = 10000
)

// ParseSitemap parses sitemap XML content and returns a list of discovered URLs.
// It supports both standard sitemaps (<urlset>) and sitemap index files (<sitemapindex>).
// The function also handles gzip-compressed sitemap content automatically.
func ParseSitemap(content io.Reader) []string {
	urls := make([]string, 0)

	// Read the content to check if it's gzip-compressed
	data, err := io.ReadAll(content)
	if err != nil {
		return urls
	}

	// Create a new reader from the data
	reader := strings.NewReader(string(data))

	// Check if content is gzip-compressed (magic bytes: 0x1f 0x8b)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gzReader, err := gzip.NewReader(strings.NewReader(string(data)))
		if err != nil {
			return urls
		}
		defer gzReader.Close()

		decompressed, err := io.ReadAll(gzReader)
		if err != nil {
			return urls
		}
		reader = strings.NewReader(string(decompressed))
	}

	// Try parsing as standard sitemap first
	var urlset URLSet
	decoder := xml.NewDecoder(reader)
	if err := decoder.Decode(&urlset); err == nil && len(urlset.URLs) > 0 {
		for i, u := range urlset.URLs {
			if i >= MaxSitemapURLs {
				break
			}
			if u.Loc != "" {
				urls = append(urls, u.Loc)
			}
		}
		return urls
	}

	// Reset reader and try parsing as sitemap index
	reader.Seek(0, io.SeekStart)
	var sitemapIndex SitemapIndex
	decoder = xml.NewDecoder(reader)
	if err := decoder.Decode(&sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		for i, s := range sitemapIndex.Sitemaps {
			if i >= MaxSitemapURLs {
				break
			}
			if s.Loc != "" {
				urls = append(urls, s.Loc)
			}
		}
		return urls
	}

	return urls
}
