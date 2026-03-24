// Package proxy provides HTTP traffic interception functionality for security testing.
package proxy

import (
	"container/list"
	"crypto/tls"
	"sync"
)

const (
	// DefaultCacheSize is the default maximum number of certificates to cache.
	DefaultCacheSize = 1000
)

// CertCache provides an LRU cache for TLS certificates.
type CertCache struct {
	mu      sync.RWMutex
	cache   map[string]*list.Element
	lru     *list.List
	maxSize int
	ca      *CertificateAuthority
}

type cacheEntry struct {
	hostname string
	cert     *tls.Certificate
}

// NewCertCache creates a new certificate cache with the given CA and maximum size.
func NewCertCache(ca *CertificateAuthority, maxSize int) *CertCache {
	if maxSize <= 0 {
		maxSize = DefaultCacheSize
	}
	return &CertCache{
		cache:   make(map[string]*list.Element),
		lru:     list.New(),
		maxSize: maxSize,
		ca:      ca,
	}
}

// GetOrGenerate returns a cached certificate for the hostname, or generates a new one.
func (c *CertCache) GetOrGenerate(hostname string) (*tls.Certificate, error) {
	// Try to get from cache first (read lock)
	c.mu.RLock()
	elem, found := c.cache[hostname]
	c.mu.RUnlock()

	if found {
		// Move to front of LRU (needs write lock)
		c.mu.Lock()
		c.lru.MoveToFront(elem)
		cert := elem.Value.(*cacheEntry).cert
		c.mu.Unlock()
		return cert, nil
	}

	// Generate new certificate
	cert, err := c.ca.GenerateCertificate(hostname)
	if err != nil {
		return nil, err
	}

	// Add to cache
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if another goroutine added it while we were generating
	if elem, found := c.cache[hostname]; found {
		c.lru.MoveToFront(elem)
		return elem.Value.(*cacheEntry).cert, nil
	}

	// Evict oldest entries if cache is full
	for c.lru.Len() >= c.maxSize {
		oldest := c.lru.Back()
		if oldest != nil {
			entry := oldest.Value.(*cacheEntry)
			delete(c.cache, entry.hostname)
			c.lru.Remove(oldest)
		}
	}

	// Add new entry
	entry := &cacheEntry{
		hostname: hostname,
		cert:     cert,
	}
	elem = c.lru.PushFront(entry)
	c.cache[hostname] = elem

	return cert, nil
}

// Get retrieves a certificate from the cache without generating.
func (c *CertCache) Get(hostname string) (*tls.Certificate, bool) {
	c.mu.RLock()
	elem, found := c.cache[hostname]
	c.mu.RUnlock()

	if !found {
		return nil, false
	}

	c.mu.Lock()
	c.lru.MoveToFront(elem)
	cert := elem.Value.(*cacheEntry).cert
	c.mu.Unlock()

	return cert, true
}

// Put adds a certificate to the cache.
func (c *CertCache) Put(hostname string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already exists
	if elem, found := c.cache[hostname]; found {
		elem.Value.(*cacheEntry).cert = cert
		c.lru.MoveToFront(elem)
		return
	}

	// Evict oldest entries if cache is full
	for c.lru.Len() >= c.maxSize {
		oldest := c.lru.Back()
		if oldest != nil {
			entry := oldest.Value.(*cacheEntry)
			delete(c.cache, entry.hostname)
			c.lru.Remove(oldest)
		}
	}

	// Add new entry
	entry := &cacheEntry{
		hostname: hostname,
		cert:     cert,
	}
	elem := c.lru.PushFront(entry)
	c.cache[hostname] = elem
}

// Size returns the number of certificates in the cache.
func (c *CertCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lru.Len()
}

// Clear removes all certificates from the cache.
func (c *CertCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*list.Element)
	c.lru.Init()
}

// Remove removes a certificate from the cache.
func (c *CertCache) Remove(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, found := c.cache[hostname]; found {
		delete(c.cache, hostname)
		c.lru.Remove(elem)
	}
}
