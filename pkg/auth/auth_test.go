package auth

import (
	"net/http"
	"testing"
)

func TestAuthConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		config *AuthConfig
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   true,
		},
		{
			name:   "empty config",
			config: &AuthConfig{},
			want:   true,
		},
		{
			name: "with auth header",
			config: &AuthConfig{
				AuthHeader: "Authorization: Bearer token123",
			},
			want: false,
		},
		{
			name: "with bearer token",
			config: &AuthConfig{
				BearerToken: "token123",
			},
			want: false,
		},
		{
			name: "with basic auth",
			config: &AuthConfig{
				BasicAuth: "user:pass",
			},
			want: false,
		},
		{
			name: "with cookies",
			config: &AuthConfig{
				Cookies: []string{"session=abc123"},
			},
			want: false,
		},
		{
			name: "with empty cookies slice",
			config: &AuthConfig{
				Cookies: []string{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsEmpty(); got != tt.want {
				t.Errorf("AuthConfig.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthConfig_ApplyToRequest(t *testing.T) {
	tests := []struct {
		name           string
		config         *AuthConfig
		expectedHeader map[string]string
		expectedCookie map[string]string
	}{
		{
			name:   "nil config",
			config: nil,
			expectedHeader: map[string]string{},
			expectedCookie: map[string]string{},
		},
		{
			name: "bearer token",
			config: &AuthConfig{
				BearerToken: "mytoken123",
			},
			expectedHeader: map[string]string{
				"Authorization": "Bearer mytoken123",
			},
			expectedCookie: map[string]string{},
		},
		{
			name: "basic auth",
			config: &AuthConfig{
				BasicAuth: "admin:secret",
			},
			expectedHeader: map[string]string{
				"Authorization": "Basic YWRtaW46c2VjcmV0", // base64("admin:secret")
			},
			expectedCookie: map[string]string{},
		},
		{
			name: "custom auth header",
			config: &AuthConfig{
				AuthHeader: "X-API-Key: abc123",
			},
			expectedHeader: map[string]string{
				"X-Api-Key": "abc123",
			},
			expectedCookie: map[string]string{},
		},
		{
			name: "cookie",
			config: &AuthConfig{
				Cookies: []string{"session=xyz789"},
			},
			expectedHeader: map[string]string{},
			expectedCookie: map[string]string{
				"session": "xyz789",
			},
		},
		{
			name: "multiple cookies",
			config: &AuthConfig{
				Cookies: []string{"session=xyz789", "user_id=123"},
			},
			expectedHeader: map[string]string{},
			expectedCookie: map[string]string{
				"session": "xyz789",
				"user_id": "123",
			},
		},
		{
			name: "combined auth methods",
			config: &AuthConfig{
				BearerToken: "token123",
				Cookies:     []string{"session=abc"},
			},
			expectedHeader: map[string]string{
				"Authorization": "Bearer token123",
			},
			expectedCookie: map[string]string{
				"session": "abc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			tt.config.ApplyToRequest(req)

			// Check headers
			for key, expectedValue := range tt.expectedHeader {
				got := req.Header.Get(key)
				if got != expectedValue {
					t.Errorf("Header %s = %q, want %q", key, got, expectedValue)
				}
			}

			// Check cookies
			for name, expectedValue := range tt.expectedCookie {
				cookie, err := req.Cookie(name)
				if err != nil {
					t.Errorf("Expected cookie %s not found", name)
					continue
				}
				if cookie.Value != expectedValue {
					t.Errorf("Cookie %s = %q, want %q", name, cookie.Value, expectedValue)
				}
			}
		})
	}
}

func TestAuthConfig_Summary(t *testing.T) {
	tests := []struct {
		name   string
		config *AuthConfig
		want   string
	}{
		{
			name:   "nil config",
			config: nil,
			want:   "none",
		},
		{
			name:   "empty config",
			config: &AuthConfig{},
			want:   "none",
		},
		{
			name: "bearer token",
			config: &AuthConfig{
				BearerToken: "secret-token",
			},
			want: "bearer:***",
		},
		{
			name: "basic auth",
			config: &AuthConfig{
				BasicAuth: "admin:password",
			},
			want: "basic:admin:***",
		},
		{
			name: "custom header",
			config: &AuthConfig{
				AuthHeader: "X-API-Key: secret",
			},
			want: "header:X-API-Key",
		},
		{
			name: "single cookie",
			config: &AuthConfig{
				Cookies: []string{"session=abc123"},
			},
			want: "cookies:[session]",
		},
		{
			name: "multiple cookies",
			config: &AuthConfig{
				Cookies: []string{"session=abc123", "user=john"},
			},
			want: "cookies:[session,user]",
		},
		{
			name: "combined",
			config: &AuthConfig{
				BearerToken: "token",
				Cookies:     []string{"session=abc"},
			},
			want: "bearer:***, cookies:[session]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Summary(); got != tt.want {
				t.Errorf("AuthConfig.Summary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthConfig_BearerOverridesBasic(t *testing.T) {
	// When both bearer and basic are set, bearer should be applied last
	// (overriding the Authorization header set by basic auth)
	config := &AuthConfig{
		BasicAuth:   "user:pass",
		BearerToken: "mytoken",
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	config.ApplyToRequest(req)

	got := req.Header.Get("Authorization")
	want := "Bearer mytoken"
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestAuthConfig_CustomHeaderFormat(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantValue  string
	}{
		{
			name:       "standard format",
			authHeader: "Authorization: Bearer token",
			wantKey:    "Authorization",
			wantValue:  "Bearer token",
		},
		{
			name:       "with extra spaces",
			authHeader: "Authorization:   Bearer token  ",
			wantKey:    "Authorization",
			wantValue:  "Bearer token",
		},
		{
			name:       "custom header",
			authHeader: "X-Custom-Auth: my-secret-value",
			wantKey:    "X-Custom-Auth",
			wantValue:  "my-secret-value",
		},
		{
			name:       "invalid format (no colon)",
			authHeader: "InvalidHeader",
			wantKey:    "",
			wantValue:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &AuthConfig{
				AuthHeader: tt.authHeader,
			}

			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			config.ApplyToRequest(req)

			if tt.wantKey != "" {
				got := req.Header.Get(tt.wantKey)
				if got != tt.wantValue {
					t.Errorf("Header %s = %q, want %q", tt.wantKey, got, tt.wantValue)
				}
			}
		})
	}
}
