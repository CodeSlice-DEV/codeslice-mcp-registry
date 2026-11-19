package validators

import "errors"

// Error messages for validation
var (
	// Repository validation errors
	ErrInvalidRepositoryURL = errors.New("invalid repository URL")
	ErrInvalidSubfolderPath = errors.New("invalid subfolder path")

	// Package validation errors
	ErrPackageNameHasSpaces  = errors.New("package name cannot contain spaces")
	ErrReservedVersionString = errors.New("version string 'latest' is reserved and cannot be used")
	ErrVersionLooksLikeRange = errors.New("version must be a specific version, not a range")

	// Transport validation errors
	ErrInvalidPackageTransportURL = errors.New("invalid package transport URL")
	ErrInvalidRemoteURL           = errors.New("invalid remote URL")

	// Registry validation errors
	ErrUnsupportedRegistryBaseURL   = errors.New("unsupported registry base URL")
	ErrMismatchedRegistryTypeAndURL = errors.New("registry type and base URL do not match")

	// Argument validation errors
	ErrNamedArgumentNameRequired     = errors.New("named argument name is required")
	ErrInvalidNamedArgumentName      = errors.New("invalid named argument name format")
	ErrArgumentValueStartsWithName   = errors.New("argument value cannot start with the argument name")
	ErrArgumentDefaultStartsWithName = errors.New("argument default cannot start with the argument name")

	// Server name validation errors
	ErrMultipleSlashesInServerName = errors.New("server name cannot contain multiple slashes")
	ErrInvalidServerNameFormat     = errors.New("server name format is invalid")

	// Security profile validation errors
	ErrInvalidEntraResource  = errors.New("entraOboResource must be a valid URI starting with api:// or https://")
	ErrEmptyDelegatedScope   = errors.New("requiredDelegatedScopes cannot contain empty scope strings")
	ErrInvalidScopeFormat    = errors.New("invalid scope format: must contain alphanumeric characters, dots, colons, or underscores")
	ErrInvalidBlindingLevel  = errors.New("blindingClearanceLevel must be one of: unblinded, blinded_study, public, restricted")
	ErrInvalidDataPackDigest = errors.New("requiredDataPackDigests must contain valid 64-character lowercase hex SHA-256 digests")
)

// RepositorySource represents valid repository sources
type RepositorySource string

const (
	SourceGitHub RepositorySource = "github"
	SourceGitLab RepositorySource = "gitlab"
)

const (
	SchemeHTTPS = "https"
)
