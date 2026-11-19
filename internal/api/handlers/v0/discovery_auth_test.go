package v0_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	v0 "github.com/modelcontextprotocol/registry/internal/api/handlers/v0"
	"github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
	"github.com/modelcontextprotocol/registry/internal/database"
	"github.com/modelcontextprotocol/registry/internal/service"
	apiv0 "github.com/modelcontextprotocol/registry/pkg/api/v0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRegistryService struct {
	lastFilter *database.ServerFilter
}

func (m *mockRegistryService) ListServers(_ context.Context, filter *database.ServerFilter, _ string, _ int) ([]*apiv0.ServerResponse, string, error) {
	m.lastFilter = filter
	return []*apiv0.ServerResponse{}, "", nil
}

func (m *mockRegistryService) GetServerByName(_ context.Context, _ string, _ bool) (*apiv0.ServerResponse, error) {
	return nil, database.ErrNotFound
}

func (m *mockRegistryService) GetServerByNameAndVersion(_ context.Context, _ string, _ string, _ bool) (*apiv0.ServerResponse, error) {
	return nil, database.ErrNotFound
}

func (m *mockRegistryService) GetAllVersionsByServerName(_ context.Context, _ string, _ bool) ([]*apiv0.ServerResponse, error) {
	return nil, database.ErrNotFound
}

func (m *mockRegistryService) CreateServer(_ context.Context, _ *apiv0.ServerJSON) (*apiv0.ServerResponse, error) {
	return &apiv0.ServerResponse{}, nil
}

func (m *mockRegistryService) UpdateServer(_ context.Context, _, _ string, _ *apiv0.ServerJSON, _ *service.StatusChangeRequest) (*apiv0.ServerResponse, error) {
	return &apiv0.ServerResponse{}, nil
}

func (m *mockRegistryService) UpdateServerStatus(_ context.Context, _, _ string, _ *service.StatusChangeRequest) (*apiv0.ServerResponse, error) {
	return &apiv0.ServerResponse{}, nil
}

func (m *mockRegistryService) UpdateAllVersionsStatus(_ context.Context, _ string, _ *service.StatusChangeRequest) ([]*apiv0.ServerResponse, error) {
	return []*apiv0.ServerResponse{}, nil
}

func TestDiscoveryAuthenticationEnforcement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_ = pub
	seed := priv.Seed()
	privHex := hex.EncodeToString(seed)

	cfg := &config.Config{
		JWTPrivateKey:           privHex,
		RequireAuthForDiscovery: true,
	}

	jwtMgr := auth.NewJWTManager(cfg)
	tokenResp, err := jwtMgr.GenerateTokenResponse(context.Background(), auth.JWTClaims{
		AuthMethod:        auth.MethodOIDC,
		AuthMethodSubject: "test-user@tenant-alpha.com",
		TenantID:          "tenant-alpha-uuid",
		Permissions: []auth.Permission{
			{Action: auth.PermissionActionPublish, ResourcePattern: "*"},
		},
	})
	require.NoError(t, err)

	mockSvc := &mockRegistryService{}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Test API", "1.0.0"))
	v0.RegisterServersEndpoints(api, "/v0", mockSvc, cfg)

	t.Run("unauthenticated request to /v0/servers returns 401 Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v0/servers", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Authentication required for discovery")
	})

	t.Run("invalid token format returns 401 Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v0/servers", nil)
		req.Header.Set("Authorization", "InvalidFormat token123")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid Authorization header format")
	})

	t.Run("valid bearer token returns 200 OK and scopes tenant_id filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v0/servers", nil)
		req.Header.Set("Authorization", "Bearer "+tokenResp.RegistryToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, mockSvc.lastFilter)
		require.NotNil(t, mockSvc.lastFilter.TenantID)
		assert.Equal(t, "tenant-alpha-uuid", *mockSvc.lastFilter.TenantID)
	})
}
