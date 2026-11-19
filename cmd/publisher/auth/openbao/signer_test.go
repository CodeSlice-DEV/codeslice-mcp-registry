// Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
// SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

package openbao_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/registry/cmd/publisher/auth/openbao"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSignatureProvider_Validation(t *testing.T) {
	t.Setenv("OPENBAO_ADDR", "")
	t.Setenv("BAO_ADDR", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("OPENBAO_TRANSIT_KEY", "")
	t.Setenv("VAULT_TRANSIT_KEY", "")

	_, err := openbao.GetSignatureProvider("", "", "")
	assert.ErrorContains(t, err, "openbao address is required")

	_, err = openbao.GetSignatureProvider("http://127.0.0.1:8200", "", "")
	assert.ErrorContains(t, err, "openbao transit key name is required")

	signer, err := openbao.GetSignatureProvider("http://127.0.0.1:8200", "my-key", "test-token")
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestSigner_GetSignedTimestamp(t *testing.T) {
	dummySig := []byte("deterministic-transit-signature-bytes")
	encodedSig := "vault:v1:" + base64.StdEncoding.EncodeToString(dummySig)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/transit/sign/publish-key", r.URL.Path)
		assert.Equal(t, "root-token", r.Header.Get("X-Vault-Token"))

		var req map[string]string
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)
		assert.NotEmpty(t, req["input"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]string{
				"signature": encodedSig,
			},
		})
	}))
	defer server.Close()

	signer, err := openbao.GetSignatureProvider(server.URL, "publish-key", "root-token")
	require.NoError(t, err)

	ts, sig, err := signer.GetSignedTimestamp(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, ts)
	assert.NotEmpty(t, *ts)
	assert.Equal(t, dummySig, sig)
}
