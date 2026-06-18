package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	githubDeviceCodeURL  = "https://github.com/login/device/code"
	githubAccessTokenURL = "https://github.com/login/oauth/access_token"
)

// HTTPClient is the HTTP client interface used by DeviceFlow.
// It is stubbable for testing.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// defaultClient is the package-level HTTP client.
var defaultClient HTTPClient = http.DefaultClient

// DeviceCodeResponse holds the response from GitHub's device code endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// OAuthTokenResponse holds the response from GitHub's access token endpoint.
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error,omitempty"`
}

// DeviceFlow implements the GitHub OAuth device authorization grant flow.
type DeviceFlow struct {
	ClientID string
	Client   HTTPClient
}

// NewDeviceFlow creates a DeviceFlow with the given OAuth app client ID.
func NewDeviceFlow(clientID string) *DeviceFlow {
	return &DeviceFlow{
		ClientID: clientID,
		Client:   defaultClient,
	}
}

// Start initiates the device flow by requesting a device code from GitHub.
func (d *DeviceFlow) Start() (*DeviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", d.ClientID)
	data.Set("scope", "read:user repo")

	req, err := http.NewRequest(http.MethodPost, githubDeviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create device code request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := d.Client
	if client == nil {
		client = defaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed with status %d", resp.StatusCode)
	}

	var result DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode device code response: %w", err)
	}
	return &result, nil
}

// Poll polls GitHub for an access token until the user authorizes the device.
// It blocks and should typically be run in a goroutine or with a timeout context.
func (d *DeviceFlow) Poll(deviceCode string, interval int) (*OAuthTokenResponse, error) {
	if interval < 5 {
		interval = 5
	}

	client := d.Client
	if client == nil {
		client = defaultClient
	}

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		data := url.Values{}
		data.Set("client_id", d.ClientID)
		data.Set("device_code", deviceCode)
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		req, err := http.NewRequest(http.MethodPost, githubAccessTokenURL, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("failed to create access token request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to poll access token: %w", err)
		}

		var result OAuthTokenResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to decode access token response: %w", decodeErr)
		}

		if result.Error == "authorization_pending" {
			continue
		}
		if result.Error == "slow_down" {
			interval += 5
			continue
		}
		if result.Error != "" {
			return nil, fmt.Errorf("oauth error: %s", result.Error)
		}
		if result.AccessToken != "" {
			return &result, nil
		}
	}
}
