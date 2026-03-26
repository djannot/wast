// Package crawler provides web crawling functionality for reconnaissance operations.
package crawler

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
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
// Returns (urlset URLs, sitemap index URLs) - one will be populated, the other empty.
func ParseSitemap(content io.Reader) []string {
	urlset, sitemapIndex := ParseSitemapBoth(content)
	// Return whichever has content
	if len(urlset) > 0 {
		return urlset
	}
	return sitemapIndex
}

// ParseSitemapBoth parses sitemap XML and returns both types of URLs.
// Returns (urlset URLs, sitemap index URLs).
// This allows the caller to distinguish between regular sitemaps and sitemap indexes.
func ParseSitemapBoth(content io.Reader) (urlsetURLs []string, sitemapIndexURLs []string) {
	urlsetURLs = make([]string, 0)
	sitemapIndexURLs = make([]string, 0)

	// Read the content to check if it's gzip-compressed
	data, err := io.ReadAll(content)
	if err != nil {
		return
	}

	var decompressedData []byte

	// Check if content is gzip-compressed (magic bytes: 0x1f 0x8b)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gzReader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		defer gzReader.Close()

		decompressedData, err = io.ReadAll(gzReader)
		if err != nil {
			return
		}
	} else {
		decompressedData = data
	}

	// Try parsing as standard sitemap first
	var urlset URLSet
	if err := xml.NewDecoder(bytes.NewReader(decompressedData)).Decode(&urlset); err == nil && len(urlset.URLs) > 0 {
		for i, u := range urlset.URLs {
			if i >= MaxSitemapURLs {
				break
			}
			if u.Loc != "" {
				urlsetURLs = append(urlsetURLs, u.Loc)
			}
		}
		return
	}

	// Try parsing as sitemap index
	var sitemapIndex SitemapIndex
	if err := xml.NewDecoder(bytes.NewReader(decompressedData)).Decode(&sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		for i, s := range sitemapIndex.Sitemaps {
			if i >= MaxSitemapURLs {
				break
			}
			if s.Loc != "" {
				sitemapIndexURLs = append(sitemapIndexURLs, s.Loc)
			}
		}
		return
	}

	return
}
