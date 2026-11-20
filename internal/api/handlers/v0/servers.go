package v0

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
	"github.com/modelcontextprotocol/registry/internal/database"
	"github.com/modelcontextprotocol/registry/internal/service"
	apiv0 "github.com/modelcontextprotocol/registry/pkg/api/v0"
)

const (
	errRecordNotFound = "record not found"
)

// OptionalBool is a tri-state boolean for query parameters
type OptionalBool struct {
	Value bool
	IsSet bool
}

// UnmarshalText implements encoding.TextUnmarshaler for Huma query parameter decoding
func (o *OptionalBool) UnmarshalText(text []byte) error {
	str := strings.TrimSpace(string(text))
	if str == "" {
		o.Value = false
		o.IsSet = false
		return nil
	}
	val, err := strconv.ParseBool(str)
	if err != nil {
		return err
	}
	o.Value = val
	o.IsSet = true
	return nil
}

// resolveIncludeDeleted handles the include_deleted parameter logic for list endpoints
// Returns the resolved value and an error if include_deleted=false conflicts with updated_since
func resolveIncludeDeleted(includeDeleted OptionalBool, hasUpdatedSince bool) (bool, error) {
	if hasUpdatedSince {
		// When updated_since is provided, include_deleted must be true for incremental sync
		if includeDeleted.IsSet && !includeDeleted.Value {
			return false, huma.Error400BadRequest("Cannot set include_deleted=false when using updated_since (incremental sync requires deleted servers)")
		}
		return true, nil
	}
	// Use provided value, defaults to false if not set
	return includeDeleted.Value, nil
}

// applySearchFilter rejects invalid terms before service/database work. Empty search
// retains listing behavior, and valid terms retain their original matching semantics.
func applySearchFilter(filter *database.ServerFilter, search string) error {
	if search == "" {
		return nil
	}
	if utf8.RuneCountInString(strings.TrimSpace(search)) < 3 {
		return huma.Error422UnprocessableEntity("search must contain at least 3 characters after trimming surrounding whitespace")
	}
	filter.SubstringName = &search
	return nil
}

// ListServersInput represents the input for listing servers
type ListServersInput struct {
	Authorization  string       `header:"Authorization" doc:"Bearer token for authentication" required:"false"`
	Cursor         string       `query:"cursor" doc:"Pagination cursor" required:"false" example:"server-cursor-123"`
	Limit          int          `query:"limit" doc:"Number of items per page" default:"30" minimum:"1" maximum:"100" example:"50"`
	UpdatedSince   string       `query:"updated_since" doc:"Filter servers updated since timestamp (RFC3339 datetime)" required:"false" example:"2025-08-07T13:15:04.280Z"`
	Search         string       `query:"search" doc:"Search servers by name (substring match); nonempty searches require at least 3 characters after trimming surrounding whitespace" required:"false" example:"filesystem"`
	Version        string       `query:"version" doc:"Filter by version ('latest' for latest version, or an exact version like '1.2.3')" required:"false" example:"latest"`
	IncludeDeleted OptionalBool `query:"include_deleted" doc:"Include deleted servers in results (default: false, but always true when updated_since is provided)" required:"false"`
}

// ServerDetailInput represents the input for getting server details
type ServerDetailInput struct {
	Authorization string `header:"Authorization" doc:"Bearer token for authentication" required:"false"`
	ServerName    string `path:"serverName" doc:"URL-encoded server name" example:"com.example%2Fmy-server"`
}

// ServerVersionDetailInput represents the input for getting a specific version
type ServerVersionDetailInput struct {
	Authorization  string `header:"Authorization" doc:"Bearer token for authentication" required:"false"`
	ServerName     string `path:"serverName" doc:"URL-encoded server name" example:"com.example%2Fmy-server"`
	Version        string `path:"version" doc:"URL-encoded server version" example:"1.0.0"`
	IncludeDeleted bool   `query:"include_deleted" doc:"Include deleted servers in results (default: false)" required:"false" default:"false"`
}

// ServerVersionsInput represents the input for listing all versions of a server
type ServerVersionsInput struct {
	Authorization  string `header:"Authorization" doc:"Bearer token for authentication" required:"false"`
	ServerName     string `path:"serverName" doc:"URL-encoded server name" example:"com.example%2Fmy-server"`
	IncludeDeleted bool   `query:"include_deleted" doc:"Include deleted servers in results (default: false)" required:"false" default:"false"`
}

func authenticateDiscovery(ctx context.Context, cfg *config.Config, authHeader string) (string, error) {
	if cfg == nil {
		return "", nil
	}
	if authHeader == "" {
		if cfg.RequireAuthForDiscovery {
			return "", huma.Error401Unauthorized("Authentication required for discovery")
		}
		return "", nil
	}
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || !strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
		if cfg.RequireAuthForDiscovery {
			return "", huma.Error401Unauthorized("Invalid Authorization header format. Expected 'Bearer <token>'")
		}
		return "", nil
	}
	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	jwtMgr := auth.NewJWTManager(cfg)
	claims, err := jwtMgr.ValidateToken(ctx, token)
	if err != nil {
		if cfg.RequireAuthForDiscovery {
			return "", huma.Error401Unauthorized("Invalid bearer token", err)
		}
		return "", nil
	}
	if claims == nil {
		return "", nil
	}
	return claims.TenantID, nil
}

// RegisterServersEndpoints registers all server-related endpoints with a custom path prefix
func RegisterServersEndpoints(api huma.API, pathPrefix string, registry service.RegistryService, cfg ...*config.Config) {
	var activeCfg *config.Config
	if len(cfg) > 0 && cfg[0] != nil {
		activeCfg = cfg[0]
	}

	registerListServersEndpoint(api, pathPrefix, registry, activeCfg)
	registerGetServerDetailEndpoint(api, pathPrefix, registry, activeCfg)
	registerGetServerVersionEndpoint(api, pathPrefix, registry, activeCfg)
	registerGetServerVersionsEndpoint(api, pathPrefix, registry, activeCfg)
}

func registerGetServerDetailEndpoint(api huma.API, pathPrefix string, registry service.RegistryService, activeCfg *config.Config) {
	huma.Register(api, huma.Operation{
		OperationID: "get-server" + strings.ReplaceAll(pathPrefix, "/", "-"),
		Method:      http.MethodGet,
		Path:        pathPrefix + "/servers/{serverName}",
		Summary:     "Get MCP server details",
		Description: "Get detailed information about the latest version of an MCP server",
		Tags:        []string{tagServers},
	}, func(ctx context.Context, input *ServerDetailInput) (*Response[apiv0.ServerResponse], error) {
		tenantID, authErr := authenticateDiscovery(ctx, activeCfg, input.Authorization)
		if authErr != nil {
			return nil, authErr
		}
		if tenantID != "" {
			ctx = auth.WithTenantID(ctx, tenantID)
		}

		serverName, err := url.PathUnescape(input.ServerName)
		if err != nil {
			return nil, huma.Error400BadRequest("Invalid server name encoding", err)
		}

		serverResponse, err := registry.GetServerByName(ctx, serverName, false)
		if err != nil {
			if err.Error() == errRecordNotFound || errors.Is(err, database.ErrNotFound) {
				return nil, huma.Error404NotFound("Server not found")
			}
			log.Printf("get server details (%q) failed: %v", serverName, err)
			return nil, huma.Error500InternalServerError("Failed to get server details")
		}

		return &Response[apiv0.ServerResponse]{
			Body: *serverResponse,
		}, nil
	})
}

func registerListServersEndpoint(api huma.API, pathPrefix string, registry service.RegistryService, activeCfg *config.Config) {
	huma.Register(api, huma.Operation{
		OperationID: "list-servers" + strings.ReplaceAll(pathPrefix, "/", "-"),
		Method:      http.MethodGet,
		Path:        pathPrefix + "/servers",
		Summary:     "List MCP servers",
		Description: "Get a paginated list with one record per server version. Without a version filter, results include superseded versions, including when search is provided. " +
			"Results are ordered by server name, then by version string, both ascending. Versions are compared as text, not by semantic version or publication date; the first result for a server is not necessarily its latest version. " +
			"Use version=latest to return only the latest version of each matching server. Keep the same filters when following metadata.nextCursor.",
		Tags: []string{tagServers},
	}, func(ctx context.Context, input *ListServersInput) (*Response[apiv0.ServerListResponse], error) {
		tenantID, authErr := authenticateDiscovery(ctx, activeCfg, input.Authorization)
		if authErr != nil {
			return nil, authErr
		}

		filter := &database.ServerFilter{}
		if tenantID != "" {
			ctx = auth.WithTenantID(ctx, tenantID)
			filter.TenantID = &tenantID
		}

		if input.UpdatedSince != "" {
			if updatedTime, err := time.Parse(time.RFC3339, input.UpdatedSince); err == nil {
				filter.UpdatedSince = &updatedTime
			} else {
				return nil, huma.Error400BadRequest("Invalid updated_since format: expected RFC3339 timestamp (e.g., 2025-08-07T13:15:04.280Z)")
			}
		}

		if err := applySearchFilter(filter, input.Search); err != nil {
			return nil, err
		}

		if input.Version != "" {
			if input.Version == "latest" {
				isLatest := true
				filter.IsLatest = &isLatest
			} else {
				filter.Version = &input.Version
			}
		}

		includeDeleted, err := resolveIncludeDeleted(input.IncludeDeleted, filter.UpdatedSince != nil)
		if err != nil {
			return nil, err
		}
		filter.IncludeDeleted = &includeDeleted

		encoded := activeCfg != nil && activeCfg.PreparedListingJSON
		body, err := listServersBody(ctx, registry, filter, input, encoded)
		if err != nil {
			return nil, ListServersError(ctx, err)
		}
		return &Response[apiv0.ServerListResponse]{Body: body}, nil
	})
}

func registerGetServerVersionEndpoint(api huma.API, pathPrefix string, registry service.RegistryService, activeCfg *config.Config) {
	huma.Register(api, huma.Operation{
		OperationID: "get-server-version" + strings.ReplaceAll(pathPrefix, "/", "-"),
		Method:      http.MethodGet,
		Path:        pathPrefix + "/servers/{serverName}/versions/{version}",
		Summary:     "Get specific MCP server version",
		Description: "Get detailed information about a specific version of an MCP server. Use the special version 'latest' to get the latest version.",
		Tags:        []string{tagServers},
	}, func(ctx context.Context, input *ServerVersionDetailInput) (*Response[apiv0.ServerResponse], error) {
		tenantID, authErr := authenticateDiscovery(ctx, activeCfg, input.Authorization)
		if authErr != nil {
			return nil, authErr
		}
		if tenantID != "" {
			ctx = auth.WithTenantID(ctx, tenantID)
		}

		serverName, err := url.PathUnescape(input.ServerName)
		if err != nil {
			return nil, huma.Error400BadRequest("Invalid server name encoding", err)
		}

		version, err := url.PathUnescape(input.Version)
		if err != nil {
			return nil, huma.Error400BadRequest("Invalid version encoding", err)
		}

		var serverResponse *apiv0.ServerResponse
		if version == "latest" {
			serverResponse, err = registry.GetServerByName(ctx, serverName, input.IncludeDeleted)
		} else {
			serverResponse, err = registry.GetServerByNameAndVersion(ctx, serverName, version, input.IncludeDeleted)
		}

		if err != nil {
			if err.Error() == errRecordNotFound || errors.Is(err, database.ErrNotFound) {
				return nil, huma.Error404NotFound("Server not found")
			}
			log.Printf("get server details (%q/%q) failed: %v", serverName, version, err)
			return nil, huma.Error500InternalServerError("Failed to get server details")
		}

		return &Response[apiv0.ServerResponse]{
			Body: *serverResponse,
		}, nil
	})
}

func registerGetServerVersionsEndpoint(api huma.API, pathPrefix string, registry service.RegistryService, activeCfg *config.Config) {
	huma.Register(api, huma.Operation{
		OperationID: "get-server-versions" + strings.ReplaceAll(pathPrefix, "/", "-"),
		Method:      http.MethodGet,
		Path:        pathPrefix + "/servers/{serverName}/versions",
		Summary:     "Get all versions of an MCP server",
		Description: "Get all available versions for a specific MCP server",
		Tags:        []string{tagServers},
	}, func(ctx context.Context, input *ServerVersionsInput) (*Response[apiv0.ServerListResponse], error) {
		tenantID, authErr := authenticateDiscovery(ctx, activeCfg, input.Authorization)
		if authErr != nil {
			return nil, authErr
		}
		if tenantID != "" {
			ctx = auth.WithTenantID(ctx, tenantID)
		}

		serverName, err := url.PathUnescape(input.ServerName)
		if err != nil {
			return nil, huma.Error400BadRequest("Invalid server name encoding", err)
		}

		servers, err := registry.GetAllVersionsByServerName(ctx, serverName, input.IncludeDeleted)
		if err != nil {
			if err.Error() == errRecordNotFound || errors.Is(err, database.ErrNotFound) {
				return nil, huma.Error404NotFound("Server not found")
			}
			log.Printf("get server versions (%q) failed: %v", serverName, err)
			return nil, huma.Error500InternalServerError("Failed to get server versions")
		}

		serverValues := make([]apiv0.ServerResponse, len(servers))
		for i, server := range servers {
			serverValues[i] = *server
		}

		return &Response[apiv0.ServerListResponse]{
			Body: apiv0.ServerListResponse{
				Servers: serverValues,
				Metadata: apiv0.Metadata{
					Count: len(servers),
				},
			},
		}, nil
	})
}

// Encoded responses are enabled only by the production router, which disables
// Huma's schema-link transformer. That transformer reconstructs structs from
// exported fields and cannot preserve a private serialized representation.
func listServersBody(ctx context.Context, registry service.RegistryService, filter *database.ServerFilter, input *ListServersInput, encoded bool) (apiv0.ServerListResponse, error) {
	if fast, ok := registry.(interface {
		ListServersJSON(context.Context, *database.ServerFilter, string, int) (apiv0.ServerListResponse, error)
	}); ok && encoded {
		return fast.ListServersJSON(ctx, filter, input.Cursor, input.Limit)
	}
	servers, next, err := registry.ListServers(ctx, filter, input.Cursor, input.Limit)
	if err != nil {
		return apiv0.ServerListResponse{}, err
	}
	values := make([]apiv0.ServerResponse, len(servers))
	for i, server := range servers {
		values[i] = *server
	}
	return apiv0.ServerListResponse{Servers: values, Metadata: apiv0.Metadata{Count: len(values), NextCursor: next}}, nil
}
