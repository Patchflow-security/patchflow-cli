package api

import (
	"fmt"
	"net/http"
	"time"
)

// Client is an HTTP client for the PatchFlow API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewClient creates a new API client with a default 30-second timeout.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: token,
	}
}

// NewClientWithHTTP creates a new API client with a custom HTTP client.
func NewClientWithHTTP(baseURL, token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		token:      token,
	}
}

// SetAuthHeader sets the Authorization header on the request.
func (c *Client) SetAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
}

// Error represents an API error response.
type Error struct {
	StatusCode int
	Message    string
	Code       string
}

// Error returns a formatted error string.
func (e *Error) Error() string {
	return fmt.Sprintf("api error %d (%s): %s", e.StatusCode, e.Code, e.Message)
}
