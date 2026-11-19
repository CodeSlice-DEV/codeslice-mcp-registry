package openbao

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/registry/cmd/publisher/auth"
)

// Signer implements auth.Signer using OpenSSF OpenBao Transit secrets engine.
type Signer struct {
	address string
	keyName string
	token   string
	client  *http.Client
}

// NewSigner returns an OpenBao Transit Signer.
func NewSigner(address, token, keyName string) (auth.Signer, error) {
	return GetSignatureProvider(address, keyName, token)
}

// GetSignatureProvider validates parameters and returns an OpenBao Transit Signer.
func GetSignatureProvider(address, keyName, token string) (auth.Signer, error) {
	if address == "" {
		address = os.Getenv("OPENBAO_ADDR")
		if address == "" {
			address = os.Getenv("BAO_ADDR")
		}
		if address == "" {
			address = os.Getenv("VAULT_ADDR")
		}
	}
	if address == "" {
		return nil, fmt.Errorf("openbao address is required (use --openbao-addr or OPENBAO_ADDR)")
	}

	if keyName == "" {
		keyName = os.Getenv("OPENBAO_TRANSIT_KEY")
		if keyName == "" {
			keyName = os.Getenv("VAULT_TRANSIT_KEY")
		}
	}
	if keyName == "" {
		return nil, fmt.Errorf("openbao transit key name is required (use --openbao-key or OPENBAO_TRANSIT_KEY)")
	}

	if token == "" {
		token = os.Getenv("OPENBAO_TOKEN")
		if token == "" {
			token = os.Getenv("BAO_TOKEN")
		}
		if token == "" {
			token = os.Getenv("VAULT_TOKEN")
		}
	}

	return &Signer{
		address: strings.TrimRight(address, "/"),
		keyName: keyName,
		token:   token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// GetSignedTimestamp produces a signed RFC3339 timestamp via OpenBao Transit.
func (s *Signer) GetSignedTimestamp(ctx context.Context) (*string, []byte, error) {
	timestamp := auth.GetTimestamp()
	inputBase64 := base64.StdEncoding.EncodeToString([]byte(timestamp))

	reqPayload := map[string]string{
		"input": inputBase64,
	}
	payloadBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal transit sign request: %w", err)
	}

	transitURL := fmt.Sprintf("%s/v1/transit/sign/%s", s.address, s.keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, transitURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build openbao transit HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("X-Vault-Token", s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("openbao transit request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("openbao transit signing returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var transitResponse struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&transitResponse); err != nil {
		return nil, nil, fmt.Errorf("failed to decode openbao transit response: %w", err)
	}

	// OpenBao transit signature format is vault:v1:<base64-signature>
	sigParts := strings.Split(transitResponse.Data.Signature, ":")
	if len(sigParts) < 3 {
		return nil, nil, fmt.Errorf("unexpected openbao transit signature format: %s", transitResponse.Data.Signature)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigParts[len(sigParts)-1])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode signature bytes from transit: %w", err)
	}

	return &timestamp, sigBytes, nil
}
