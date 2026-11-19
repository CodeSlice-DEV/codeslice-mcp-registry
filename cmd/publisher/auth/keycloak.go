// Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
// SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DefaultKeycloakClientID = "codeslice-publisher"
	DefaultKeycloakIssuer   = "http://localhost:8080/realms/codeslice"
)

// KeycloakDeviceAuthResponse represents the RFC 8628 device authorization response.
type KeycloakDeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// KeycloakTokenResponse represents the token response from Keycloak.
type KeycloakTokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token,omitempty"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// KeycloakProvider implements the Provider interface using RFC 8628 Device Authorization Grant with Keycloak.
type KeycloakProvider struct {
	registryURL string
	issuer      string
	clientID    string
	idToken     string
	client      *http.Client
}

// NewKeycloakProvider creates a new Keycloak RFC 8628 Device Authorization Provider.
func NewKeycloakProvider(registryURL, issuer, clientID string) *KeycloakProvider {
	if issuer == "" {
		issuer = os.Getenv("KEYCLOAK_ISSUER")
		if issuer == "" {
			issuer = os.Getenv("MCP_REGISTRY_OIDC_ISSUER")
		}
		if issuer == "" {
			issuer = DefaultKeycloakIssuer
		}
	}
	issuer = strings.TrimRight(issuer, "/")

	if clientID == "" {
		clientID = os.Getenv("KEYCLOAK_CLIENT_ID")
		if clientID == "" {
			clientID = os.Getenv("MCP_REGISTRY_OIDC_CLIENT_ID")
		}
		if clientID == "" {
			clientID = DefaultKeycloakClientID
		}
	}

	return &KeycloakProvider{
		registryURL: strings.TrimRight(registryURL, "/"),
		issuer:      issuer,
		clientID:    clientID,
		client:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the provider name.
func (k *KeycloakProvider) Name() string {
	return "keycloak"
}

// Login executes the RFC 8628 device flow against Keycloak.
func (k *KeycloakProvider) Login(ctx context.Context) error {
	deviceEndpoint := fmt.Sprintf("%s/protocol/openid-connect/auth/device", k.issuer)
	tokenEndpoint := fmt.Sprintf("%s/protocol/openid-connect/token", k.issuer)

	// Step 1: Request device authorization
	data := url.Values{}
	data.Set("client_id", k.clientID)
	data.Set("scope", "openid profile email")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create device auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to initiate device authorization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("device authorization failed (status %d): %s", resp.StatusCode, string(body))
	}

	var devResp KeycloakDeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&devResp); err != nil {
		return fmt.Errorf("failed to decode device authorization response: %w", err)
	}

	verifyURI := devResp.VerificationURI
	if devResp.VerificationURIComplete != "" {
		verifyURI = devResp.VerificationURIComplete
	}

	fmt.Fprintf(os.Stdout, "\n! Please visit the following URL to authorize this device:\n  %s\n", verifyURI)
	fmt.Fprintf(os.Stdout, "! User Code: %s\n\nWaiting for authentication...\n", devResp.UserCode)

	interval := time.Duration(devResp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	timeout := time.Duration(devResp.ExpiresIn) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	return k.pollDeviceToken(ctx, &devResp, tokenEndpoint, interval, timeout)
}

func (k *KeycloakProvider) pollDeviceToken(ctx context.Context, devResp *KeycloakDeviceAuthResponse, tokenEndpoint string, interval, timeout time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctxTimeout.Done():
			return errors.New("device authorization timed out")
		case <-ticker.C:
			tokResp, err := k.requestToken(ctxTimeout, tokenEndpoint, devResp.DeviceCode)
			if err != nil {
				continue
			}

			if tokResp.Error != "" {
				switch tokResp.Error {
				case "authorization_pending":
					continue
				case "slow_down":
					interval += 5 * time.Second
					ticker.Reset(interval)
					continue
				case "access_denied":
					return errors.New("access denied by user")
				case "expired_token":
					return errors.New("device authorization code expired")
				default:
					return fmt.Errorf("token request error: %s: %s", tokResp.Error, tokResp.ErrorDescription)
				}
			}

			if tokResp.IDToken != "" {
				k.idToken = tokResp.IDToken
				return nil
			} else if tokResp.AccessToken != "" {
				k.idToken = tokResp.AccessToken
				return nil
			}

			return errors.New("no valid token received in token response")
		}
	}
}

func (k *KeycloakProvider) requestToken(ctx context.Context, tokenEndpoint, deviceCode string) (*KeycloakTokenResponse, error) {
	tokenData := url.Values{}
	tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenData.Set("client_id", k.clientID)
	tokenData.Set("device_code", deviceCode)

	tReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tResp, err := k.client.Do(tReq)
	if err != nil {
		return nil, err
	}
	defer tResp.Body.Close()

	bodyBytes, err := io.ReadAll(tResp.Body)
	if err != nil {
		return nil, err
	}

	var tokResp KeycloakTokenResponse
	if err := json.Unmarshal(bodyBytes, &tokResp); err != nil {
		return nil, err
	}
	return &tokResp, nil
}

// GetToken retrieves the registry JWT token by exchanging the Keycloak OIDC token.
func (k *KeycloakProvider) GetToken(ctx context.Context) (string, error) {
	if k.idToken == "" {
		return "", errors.New("no Keycloak token available; run Login() first")
	}

	defer func() {
		// Zero in-memory token custody after exchange
		k.idToken = ""
	}()

	exchangeURL := fmt.Sprintf("%s/v0/auth/oidc", k.registryURL)
	reqBody, err := json.Marshal(map[string]string{
		"oidc_token": k.idToken,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal token exchange request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to exchange token with registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var regResp struct {
		RegistryToken string `json:"registry_token"`
		ExpiresAt     int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return "", fmt.Errorf("failed to decode registry token response: %w", err)
	}

	if regResp.RegistryToken == "" {
		return "", errors.New("empty registry token returned")
	}

	return regResp.RegistryToken, nil
}
