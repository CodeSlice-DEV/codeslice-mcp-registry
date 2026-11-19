// Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
// SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/registry/cmd/publisher/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeycloakProvider_LoginAndGetToken(t *testing.T) {
	var pollCount int32

	// Mock Keycloak server
	keycloakMux := http.NewServeMux()
	keycloakMux.HandleFunc("/protocol/openid-connect/auth/device", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		_ = r.ParseForm()
		assert.Equal(t, "test-client", r.FormValue("client_id"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auth.KeycloakDeviceAuthResponse{
			DeviceCode:      "dev-code-123",
			UserCode:        "USER-CODE-XYZ",
			VerificationURI: "http://localhost/auth",
			ExpiresIn:       60,
			Interval:        1,
		})
	})

	keycloakMux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_ = r.ParseForm()
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.FormValue("grant_type"))
		assert.Equal(t, "dev-code-123", r.FormValue("device_code"))

		count := atomic.AddInt32(&pollCount, 1)
		w.Header().Set("Content-Type", "application/json")

		if count == 1 {
			// First poll: authorization pending
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "authorization_pending",
			})
			return
		}

		// Second poll: authorization approved
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(auth.KeycloakTokenResponse{ //nolint:gosec // Test mock token response
			IDToken:     "mock-keycloak-id-token",
			AccessToken: "mock-keycloak-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   300,
		})
	})

	keycloakServer := httptest.NewServer(keycloakMux)
	t.Cleanup(keycloakServer.Close)

	// Mock Registry server
	registryMux := http.NewServeMux()
	registryMux.HandleFunc("/v0/auth/oidc", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "mock-keycloak-id-token", body["oidc_token"])

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // Test mock token response
			"registry_token": "registry-jwt-xyz",
			"expires_at":     time.Now().Add(1 * time.Hour).Unix(),
		})
	})

	registryServer := httptest.NewServer(registryMux)
	t.Cleanup(registryServer.Close)

	provider := auth.NewKeycloakProvider(registryServer.URL, keycloakServer.URL, "test-client")
	assert.Equal(t, "keycloak", provider.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := provider.Login(ctx)
	require.NoError(t, err)

	token, err := provider.GetToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "registry-jwt-xyz", token)

	// Second call should fail because in-memory token is zeroized
	_, err = provider.GetToken(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Keycloak token available")
}
