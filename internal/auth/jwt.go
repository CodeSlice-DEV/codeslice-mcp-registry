package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"github.com/modelcontextprotocol/registry/internal/config"
)

type tenantContextKey struct{}

// WithTenantID binds a tenant ID to a context for database and handler operations
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// TenantIDFromContext extracts the tenant ID from the context if present
func TenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(tenantContextKey{}).(string); ok {
		return v
	}
	return ""
}

// PermissionAction represents the type of action that can be performed
type PermissionAction string

const (
	PermissionActionPublish PermissionAction = "publish"
	// PermissionActionEdit allows editing server configuration.
	PermissionActionEdit PermissionAction = "edit"
)

type Permission struct {
	Action          PermissionAction `json:"action"`   // The action type (publish or edit)
	ResourcePattern string           `json:"resource"` // e.g., "io.github.username/*"
}

// JWTClaims represents the claims for the Registry JWT token
type JWTClaims struct {
	jwt.RegisteredClaims
	// Authentication method used to obtain this token
	AuthMethod        Method       `json:"auth_method"`
	AuthMethodSubject string       `json:"auth_method_sub"`
	TenantID          string       `json:"tenant_id,omitempty"`
	Permissions       []Permission `json:"permissions"`
}

type TokenResponse struct {
	RegistryToken string `json:"registry_token"`
	ExpiresAt     int    `json:"expires_at"`
}

type cachedVerifier struct {
	verifier  *oidc.IDTokenVerifier
	createdAt time.Time
}

// JWTManager handles JWT token operations and OIDC validation
type JWTManager struct {
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	tokenDuration time.Duration

	// OIDC Configurations
	oidcEnabled              bool
	oidcIssuer               string
	oidcClientID             string
	oidcPublishPerms         string
	oidcEditPerms            string
	oidcMsMultiTenantEnabled bool
	oidcAllowedTenants       []string
	oidcAllowedIssuers       []string
	oidcGroupsClaim          string
	oidcRoleMapping          map[string][]Permission
	oidcJwksFile             string
	oidcJwksJSON             string
	environmentTier          string

	// Bounded, thread-safe LRU/TTL verifier cache
	cacheMu        sync.RWMutex
	verifiersCache map[string]*cachedVerifier
	cacheTTL       time.Duration
	maxCacheSize   int
}

var (
	ephemeralKeyOnce sync.Once
	ephemeralPubKey  ed25519.PublicKey
	ephemeralPrivKey ed25519.PrivateKey
)

func NewJWTManager(cfg *config.Config) *JWTManager {
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	if cfg.JWTPrivateKey != "" {
		seed, err := hex.DecodeString(cfg.JWTPrivateKey)
		if err != nil {
			panic(fmt.Sprintf("JWTPrivateKey must be a valid hex-encoded string: %v", err))
		}
		if len(seed) != ed25519.SeedSize {
			panic(fmt.Sprintf("JWTPrivateKey seed must be exactly %d bytes for Ed25519, got %d bytes", ed25519.SeedSize, len(seed)))
		}
		privateKey = ed25519.NewKeyFromSeed(seed)
		publicKey = privateKey.Public().(ed25519.PublicKey)
	} else {
		// Secure process-wide ephemeral key pair generation when no raw private key is provided in process memory
		ephemeralKeyOnce.Do(func() {
			var err error
			ephemeralPubKey, ephemeralPrivKey, err = ed25519.GenerateKey(nil)
			if err != nil {
				panic(fmt.Sprintf("failed to generate ephemeral Ed25519 key pair: %v", err))
			}
		})
		publicKey = ephemeralPubKey
		privateKey = ephemeralPrivKey
	}

	allowedTenants := []string{}
	if cfg.OIDCAllowedTenants != "" {
		for _, t := range strings.Split(cfg.OIDCAllowedTenants, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				allowedTenants = append(allowedTenants, t)
			}
		}
	}

	allowedIssuers := []string{}
	if cfg.OIDCAllowedIssuers != "" {
		for _, i := range strings.Split(cfg.OIDCAllowedIssuers, ",") {
			i = strings.TrimSpace(i)
			if i != "" {
				allowedIssuers = append(allowedIssuers, i)
			}
		}
	}

	roleMapping := make(map[string][]Permission)
	if cfg.OIDCRoleMappingJSON != "" {
		_ = json.Unmarshal([]byte(cfg.OIDCRoleMappingJSON), &roleMapping)
	}

	groupsClaim := cfg.OIDCGroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	return &JWTManager{
		privateKey:               privateKey,
		publicKey:                publicKey,
		tokenDuration:            5 * time.Minute, // 5-minute tokens as per requirements
		oidcEnabled:              cfg.OIDCEnabled,
		oidcIssuer:               cfg.OIDCIssuer,
		oidcClientID:             cfg.OIDCClientID,
		oidcPublishPerms:         cfg.OIDCPublishPerms,
		oidcEditPerms:            cfg.OIDCEditPerms,
		oidcMsMultiTenantEnabled: cfg.OIDCMicrosoftMultiTenantEnabled,
		oidcAllowedTenants:       allowedTenants,
		oidcAllowedIssuers:       allowedIssuers,
		oidcGroupsClaim:          groupsClaim,
		oidcRoleMapping:          roleMapping,
		oidcJwksFile:             cfg.OIDCJWKSFile,
		oidcJwksJSON:             cfg.OIDCJWKSJSON,
		environmentTier:          cfg.EnvironmentTier,
		verifiersCache:           make(map[string]*cachedVerifier),
		cacheTTL:                 1 * time.Hour,
		maxCacheSize:             100,
	}
}

type staticJWKSTransport struct {
	issuer   string
	jwksJSON []byte
}

func (t *staticJWKSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")

	if strings.HasSuffix(req.URL.Path, "/.well-known/openid-configuration") {
		body := fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q,"response_types_supported":["id_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","EdDSA"]}`,
			t.issuer, strings.TrimRight(t.issuer, "/")+"/keys")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Request:    req,
		}, nil
	}

	if strings.HasSuffix(req.URL.Path, "/keys") || strings.HasSuffix(req.URL.Path, "/jwks.json") || strings.HasSuffix(req.URL.Path, "/discovery/v2.0/keys") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader(t.jwksJSON)),
			Request:    req,
		}, nil
	}

	return nil, fmt.Errorf("static JWKS transport: unexpected offline request to %s", req.URL.String())
}

// getOIDCVerifier returns a thread-safe, cached IDTokenVerifier for a given issuer
func (j *JWTManager) getOIDCVerifier(ctx context.Context, issuer string) (*oidc.IDTokenVerifier, error) {
	if !j.oidcEnabled {
		return nil, fmt.Errorf("OIDC is not enabled")
	}

	if issuer == "" {
		issuer = j.oidcIssuer
	}

	// SSRF Protection: Validate issuer against allowed issuers before making any network call
	if !j.isIssuerAllowed(issuer) {
		slog.Warn("OIDC authentication blocked by SSRF whitelist", "issuer", issuer)
		return nil, fmt.Errorf("issuer %q is not in the allowed OIDC issuers whitelist", issuer)
	}

	cacheKey := issuer + ":" + j.oidcClientID

	// Read lock check
	j.cacheMu.RLock()
	entry, exists := j.verifiersCache[cacheKey]
	j.cacheMu.RUnlock()

	if exists && time.Since(entry.createdAt) < j.cacheTTL {
		return entry.verifier, nil
	}

	// Write lock block
	j.cacheMu.Lock()
	defer j.cacheMu.Unlock()

	// Double-check under write lock
	entry, exists = j.verifiersCache[cacheKey]
	if exists && time.Since(entry.createdAt) < j.cacheTTL {
		return entry.verifier, nil
	}

	// Bounded initialization timeout to prevent hanging the HTTP server
	initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// If offline JWKS is configured, inject static transport to prevent external network calls (#2112)
	if j.oidcJwksJSON != "" || j.oidcJwksFile != "" {
		jwksBytes := []byte(j.oidcJwksJSON)
		if j.oidcJwksFile != "" {
			if data, err := os.ReadFile(j.oidcJwksFile); err == nil {
				jwksBytes = data
			}
		}
		if len(jwksBytes) > 0 {
			transport := &staticJWKSTransport{
				issuer:   issuer,
				jwksJSON: jwksBytes,
			}
			client := &http.Client{Transport: transport}
			initCtx = oidc.ClientContext(initCtx, client)
		}
	}

	// Strict OIDC provider initialization - zero SkipIssuerCheck bypasses
	provider, err := oidc.NewProvider(initCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider %q: %w", issuer, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: j.oidcClientID})

	// Bounded LRU cache size enforcement
	if len(j.verifiersCache) >= j.maxCacheSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range j.verifiersCache {
			if oldestKey == "" || v.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.createdAt
			}
		}
		if oldestKey != "" {
			delete(j.verifiersCache, oldestKey)
		}
	}

	j.verifiersCache[cacheKey] = &cachedVerifier{
		verifier:  verifier,
		createdAt: time.Now(),
	}

	return verifier, nil
}

func (j *JWTManager) isIssuerAllowed(issuer string) bool {
	if issuer == "" {
		return false
	}

	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false
	}

	// Fail closed if no allowed issuers configured
	if j.oidcIssuer == "" && len(j.oidcAllowedIssuers) == 0 {
		return false
	}

	allowedList := make([]string, 0, len(j.oidcAllowedIssuers)+1)
	if j.oidcIssuer != "" {
		allowedList = append(allowedList, j.oidcIssuer)
	}
	allowedList = append(allowedList, j.oidcAllowedIssuers...)

	for _, allowed := range allowedList {
		if allowed == "" {
			continue
		}
		if allowed == "*" {
			// Wildcard '*' is strictly forbidden in production and staging
			if j.environmentTier == "production" || j.environmentTier == "staging" {
				continue
			}
			return true
		}

		allowedU, err := url.Parse(allowed)
		if err != nil {
			continue
		}

		// Exact host match prevents domain suffix spoofing (e.g. login.enterprise.com.evil.tld)
		if !strings.EqualFold(u.Host, allowedU.Host) {
			continue
		}

		// Check path match
		allowedPath := strings.TrimSuffix(allowedU.Path, "*")
		if strings.HasPrefix(u.Path, allowedPath) || u.Path == allowedU.Path {
			return true
		}
	}
	return false
}

func (j *JWTManager) isTenantAllowed(tenantID string) bool {
	if tenantID == "" {
		return false
	}
	if len(j.oidcAllowedTenants) == 0 {
		return false
	}
	for _, allowed := range j.oidcAllowedTenants {
		if allowed == "*" {
			if j.environmentTier == "production" || j.environmentTier == "staging" {
				// Wildcard '*' is strictly forbidden in production and staging
				continue
			}
			return true
		}
		if strings.EqualFold(allowed, tenantID) {
			return true
		}
	}
	return false
}

// GenerateTokenResponse generates a new Registry JWT token
func (j *JWTManager) GenerateTokenResponse(_ context.Context, claims JWTClaims) (*TokenResponse, error) {
	// Check whether they have global permissions (used by admins)
	hasGlobalPermissions := false
	for _, perm := range claims.Permissions {
		if perm.ResourcePattern == "*" {
			hasGlobalPermissions = true
			break
		}
	}

	if !hasGlobalPermissions {
		for _, blockedNamespace := range BlockedNamespaces {
			if j.HasPermission(blockedNamespace+"/test", PermissionActionPublish, claims.Permissions) ||
				j.HasPermission(blockedNamespace+".test/x", PermissionActionPublish, claims.Permissions) {
				return nil, fmt.Errorf("your namespace is blocked. raise an issue at https://github.com/modelcontextprotocol/registry/ if you think this is a mistake")
			}
		}
	}

	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(j.tokenDuration))
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(time.Now())
	}
	if claims.Issuer == "" {
		claims.Issuer = "mcp-registry"
	}

	// Create token with claims
	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, claims)

	// Sign token with Ed25519 private key
	tokenString, err := token.SignedString(j.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &TokenResponse{
		RegistryToken: tokenString,
		ExpiresAt:     int(claims.ExpiresAt.Unix()),
	}, nil
}

// ValidateToken validates a Registry JWT token, falling back to OIDC if configured
func (j *JWTManager) ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error) {
	// Parse unverified header to route by algorithm first (algorithm confusion defense)
	parser := jwt.NewParser()
	var rawClaims jwt.MapClaims
	token, _, err := parser.ParseUnverified(tokenString, &rawClaims)

	if err == nil && token.Header["alg"] == "EdDSA" {
		return j.validateEdDSAToken(tokenString)
	}

	// Fallback to OIDC validation
	if !j.oidcEnabled {
		if err != nil {
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
		return nil, fmt.Errorf("failed to parse token: invalid signing method")
	}

	if err != nil || rawClaims == nil {
		return nil, fmt.Errorf("failed to parse token header or claims: %w", err)
	}

	return j.validateOIDCToken(ctx, tokenString, rawClaims)
}

func (j *JWTManager) validateOIDCToken(ctx context.Context, tokenString string, rawClaims jwt.MapClaims) (*JWTClaims, error) {
	// Extract token issuer for multi-tenant verification lookup
	tokenIssuer, _ := rawClaims["iss"].(string)

	verifier, oidcErr := j.getOIDCVerifier(ctx, tokenIssuer)
	if oidcErr != nil {
		slog.Warn("OIDC verifier lookup failed", "issuer", tokenIssuer, "error", oidcErr)
		return nil, fmt.Errorf("OIDC verifier initialization failed: %w", oidcErr)
	}

	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("OIDC token verification failed: %w", err)
	}

	var oidcClaims map[string]any
	if err := idToken.Claims(&oidcClaims); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC claims: %w", err)
	}

	// Extract identity from claims
	var subIdentity string
	if email, ok := oidcClaims["email"].(string); ok && email != "" {
		if emailVerified, hasVerification := oidcClaims["email_verified"].(bool); hasVerification && !emailVerified {
			slog.Warn("OIDC token rejected: unverified email claim", "email", email)
			return nil, fmt.Errorf("unverified email claim rejected")
		}
		subIdentity = email
	} else {
		subIdentity = idToken.Subject
	}

	if subIdentity == "" {
		return nil, fmt.Errorf("OIDC token claims lack subject identity")
	}

	// Dynamic RBAC Permission Mapping
	permissions := j.extractPermissionsFromClaims(oidcClaims)

	// Extract tenant ID if present in claims
	var tenantID string
	if tid, ok := oidcClaims["tenant_id"].(string); ok && tid != "" {
		tenantID = tid
	} else if tid, ok := oidcClaims["tid"].(string); ok && tid != "" {
		tenantID = tid
	}

	// Enforce tenant ID allowlist if configured
	if len(j.oidcAllowedTenants) > 0 && !j.isTenantAllowed(tenantID) {
		slog.Warn("OIDC token rejected: tenant ID not permitted", "tenant_id", tenantID)
		return nil, fmt.Errorf("unauthorized tenant ID %q", tenantID)
	}

	slog.Info("OIDC token authenticated successfully",
		"sub", subIdentity,
		"issuer", idToken.Issuer,
		"tenant_id", tenantID,
		"auth_method", MethodOIDC,
	)

	return &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   idToken.Subject,
			Issuer:    idToken.Issuer,
			IssuedAt:  jwt.NewNumericDate(idToken.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(idToken.Expiry),
		},
		AuthMethod:        MethodOIDC,
		AuthMethodSubject: subIdentity,
		TenantID:          tenantID,
		Permissions:       permissions,
	}, nil
}

func (j *JWTManager) extractPermissionsFromClaims(claims map[string]any) []Permission {
	var permissions []Permission

	// Check if dynamic role mapping configured
	if len(j.oidcRoleMapping) > 0 {
		userGroups := extractGroupNames(claims, j.oidcGroupsClaim)
		for _, group := range userGroups {
			if mappedPerms, found := j.oidcRoleMapping[group]; found {
				permissions = append(permissions, mappedPerms...)
			}
		}
		if len(permissions) > 0 {
			return permissions
		}
	}

	// Fallback to static OIDC permissions config
	if j.oidcPublishPerms != "" {
		for _, pattern := range strings.Split(j.oidcPublishPerms, ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				permissions = append(permissions, Permission{
					Action:          PermissionActionPublish,
					ResourcePattern: pattern,
				})
			}
		}
	}
	if j.oidcEditPerms != "" {
		for _, pattern := range strings.Split(j.oidcEditPerms, ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				permissions = append(permissions, Permission{
					Action:          PermissionActionEdit,
					ResourcePattern: pattern,
				})
			}
		}
	}

	return permissions
}

func extractGroupNames(claims map[string]any, groupsClaim string) []string {
	var groups []string

	for _, claimKey := range []string{groupsClaim, "groups", "roles", "wids"} {
		if val, ok := claims[claimKey]; ok {
			switch v := val.(type) {
			case []interface{}:
				for _, item := range v {
					if str, ok := item.(string); ok && str != "" {
						groups = append(groups, str)
					}
				}
			case string:
				if v != "" {
					groups = append(groups, v)
				}
			}
		}
	}
	return groups
}

func (j *JWTManager) validateEdDSAToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&JWTClaims{},
		func(_ *jwt.Token) (interface{}, error) { return j.publicKey, nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("failed to parse token: invalid token status")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token: invalid token claims mapping")
	}

	return claims, nil
}

func (j *JWTManager) HasPermission(resource string, action PermissionAction, permissions []Permission) bool {
	for _, perm := range permissions {
		if perm.Action == action && isResourceMatch(resource, perm.ResourcePattern) {
			return true
		}
	}
	return false
}

func isResourceMatch(resource, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*"))
	}
	if u, err := url.Parse(resource); err == nil && u.Scheme != "" {
		resource = u.Path
	}
	return resource == pattern
}

// IsIssuerAllowedForTest exposes isIssuerAllowed for unit testing
func (j *JWTManager) IsIssuerAllowedForTest(issuer string) bool {
	return j.isIssuerAllowed(issuer)
}

// IsTenantAllowedForTest exposes isTenantAllowed for unit testing
func (j *JWTManager) IsTenantAllowedForTest(tenantID string) bool {
	return j.isTenantAllowed(tenantID)
}
