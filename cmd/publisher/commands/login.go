// Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
// SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

package commands

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/registry/cmd/publisher/auth"
	"github.com/modelcontextprotocol/registry/cmd/publisher/auth/openbao"
)

const (
	DefaultRegistryURL  = "https://registry.modelcontextprotocol.io"
	LegacyTokenFileName = ".mcp_publisher_token" //nolint:gosec // Not a credential, just a filename
	MethodKeycloak      = "keycloak"
	MethodDNS           = "dns"
	MethodHTTP          = "http"
	MethodNone          = "none"
)

// tokenFilePath returns the path to the token file in the user's config directory
// (~/.config/mcp-publisher/token.json). It does not create the directory.
func tokenFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".config", "mcp-publisher", "token.json"), nil
}

// notAuthenticatedError returns an error guiding the user to log in,
// with a hint about the token location change for users upgrading.
func notAuthenticatedError() error {
	_, _ = fmt.Fprintln(os.Stderr, "hint: token storage moved to ~/.config/mcp-publisher/. If you recently upgraded, please re-login.")
	return errors.New("not authenticated, run 'mcp-publisher login <method>' first")
}

// ensureTokenDir creates the token directory (~/.config/mcp-publisher/) if needed.
func ensureTokenDir() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	dir := filepath.Join(homeDir, ".config", "mcp-publisher")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	return nil
}

type CryptoAlgorithm auth.CryptoAlgorithm

type SignerType string

type LoginFlags struct {
type LoginFlags struct {
	Domain           string
	PrivateKey       string
	PrivateKeyFile   string
	RegistryURL      string
	OpenBaoAddr      string
	OpenBaoKey       string
	OpenBaoToken     string
	KeycloakIssuer   string
	KeycloakClientID string
	CryptoAlgorithm  CryptoAlgorithm
	SignerType       SignerType
	ArgOffset        int
}
}

const (
	InProcessSignerType SignerType = "in-process"
	OpenBaoSignerType   SignerType = "openbao"
	NoSignerType        SignerType = "none"
)

func (c *CryptoAlgorithm) String() string {
	return string(*c)
}

func (c *CryptoAlgorithm) Set(v string) error {
	switch v {
	case string(auth.AlgorithmEd25519):
		*c = CryptoAlgorithm(auth.AlgorithmEd25519)
		return nil
	case string(auth.AlgorithmECDSAP384):
		*c = CryptoAlgorithm(auth.AlgorithmECDSAP384)
		return nil
	}
	return fmt.Errorf("invalid algorithm: %q (allowed: ed25519, ecdsap384)", v)
}

func parseLoginFlags(method string, args []string) (LoginFlags, error) {
	var flags LoginFlags
	loginFlags := flag.NewFlagSet("login", flag.ExitOnError)
	flags.CryptoAlgorithm = CryptoAlgorithm(auth.AlgorithmEd25519)
	flags.SignerType = NoSignerType
	flags.ArgOffset = 1
	loginFlags.StringVar(&flags.RegistryURL, "registry", DefaultRegistryURL, "Registry URL")

	if method == MethodKeycloak {
		loginFlags.StringVar(&flags.KeycloakIssuer, "issuer", "", "Keycloak OIDC issuer URL")
		loginFlags.StringVar(&flags.KeycloakClientID, "client-id", "", "Keycloak OIDC client ID")
	}

	if method == MethodDNS || method == MethodHTTP {
		loginFlags.StringVar(&flags.Domain, "domain", "", "Domain name")
		if len(args) > 1 {
			if args[1] == string(OpenBaoSignerType) {
				flags.SignerType = OpenBaoSignerType
				loginFlags.StringVar(&flags.OpenBaoAddr, "openbao-addr", "", "OpenBao address (e.g. http://127.0.0.1:8200)")
				loginFlags.StringVar(&flags.OpenBaoKey, "openbao-key", "", "OpenBao Transit key name")
				loginFlags.StringVar(&flags.OpenBaoToken, "openbao-token", "", "OpenBao access token")
				flags.ArgOffset = 2
			}
		}
		if flags.SignerType == NoSignerType {
			flags.SignerType = InProcessSignerType
			loginFlags.StringVar(&flags.PrivateKey, "private-key", "", "Private key (hex)")
			loginFlags.StringVar(&flags.PrivateKeyFile, "private-key-file", "", "Path to a file containing the private key (hex)")
			loginFlags.Var(&flags.CryptoAlgorithm, "algorithm", "Cryptographic algorithm (ed25519, ecdsap384)")
		}
	}
	err := loginFlags.Parse(args[flags.ArgOffset:])
	if err == nil {
		if err := validatePrivateKeyFlags(loginFlags, flags); err != nil {
			return flags, err
		}
		flags.RegistryURL = strings.TrimRight(flags.RegistryURL, "/")
	}

	return flags, err
}

// Check presence separately from value so an explicitly empty flag cannot
// select an ambient key or bypass the mutually exclusive flag check.
func validatePrivateKeyFlags(parsed *flag.FlagSet, flags LoginFlags) error {
	provided := make(map[string]bool)
	parsed.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if provided["private-key"] && provided["private-key-file"] {
		return errors.New("use --private-key or --private-key-file, not both")
	}
	if provided["private-key"] && strings.TrimSpace(flags.PrivateKey) == "" {
		return errors.New("--private-key must not be empty")
	}
	if provided["private-key-file"] && strings.TrimSpace(flags.PrivateKeyFile) == "" {
		return errors.New("--private-key-file must not be empty")
	}
	return nil
}

// resolvePrivateKey returns the hex private key for in-process signing.
// --private-key and --private-key-file are mutually exclusive; either one
// overrides the MCP_PRIVATE_KEY env var. An empty result is left for
// NewInProcessSigner to reject.
func resolvePrivateKey(flagValue, filePath string, getenv func(string) string) (string, error) {
	if flagValue != "" && filePath != "" {
		return "", errors.New("use --private-key or --private-key-file, not both")
	}
	if flagValue != "" {
		return flagValue, nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read private key file %s: %w", filePath, err)
		}
		key := strings.TrimSpace(string(data))
		if strings.HasPrefix(key, "-----BEGIN") {
			return "", fmt.Errorf("private key file %s is PEM; PEM is not supported, pass the hex private key", filePath)
		}
		if key == "" {
			return "", fmt.Errorf("private key file %s is empty", filePath)
		}
		return key, nil
	}
	return strings.TrimSpace(getenv("MCP_PRIVATE_KEY")), nil
}

func createSigner(flags LoginFlags) (auth.Signer, error) {
	switch flags.SignerType {
	case OpenBaoSignerType:
		if flags.OpenBaoAddr == "" || flags.OpenBaoKey == "" {
			return nil, errors.New("openbao signing requires --openbao-addr and --openbao-key")
		}
		return openbao.NewSigner(flags.OpenBaoAddr, flags.OpenBaoToken, flags.OpenBaoKey)
	case InProcessSignerType:
		privateKey, err := resolvePrivateKey(flags.PrivateKey, flags.PrivateKeyFile, os.Getenv)
		if err != nil {
			return nil, err
		}
		return auth.NewInProcessSigner(privateKey, auth.CryptoAlgorithm(flags.CryptoAlgorithm))
	case NoSignerType:
		return nil, errors.New("no signing provider specified")
	default:
		return nil, errors.New("unknown signing provider specified")
	}
}

func createAuthProvider(method, registryURL, domain string, flags LoginFlags, signer auth.Signer) (auth.Provider, error) {
	switch method {
	case MethodKeycloak:
		return auth.NewKeycloakProvider(registryURL, flags.KeycloakIssuer, flags.KeycloakClientID), nil
	case MethodDNS:
		if domain == "" {
			return nil, errors.New("dns authentication requires --domain")
		}
		return auth.NewDNSProvider(registryURL, domain, &signer), nil
	case MethodHTTP:
		if domain == "" {
			return nil, errors.New("http authentication requires --domain")
		}
		return auth.NewHTTPProvider(registryURL, domain, &signer), nil
	case MethodNone:
		return auth.NewNoneProvider(registryURL), nil
	default:
		return nil, fmt.Errorf("unknown authentication method: %s\nFor a list of available methods, run: mcp-publisher login", method)
	}
}

func LoginCommand(args []string) error {
	if len(args) < 1 {
		return errors.New(`authentication method required

Usage: mcp-publisher login <method> [<signing provider>]

Methods:
  keycloak          Keycloak RFC 8628 OAuth 2.0 Device Authorization Grant
  dns               DNS-based authentication (requires --domain)
  http              HTTP-based authentication (requires --domain)
  none              Anonymous authentication (for testing)

Signing providers:
  openbao           Sign using OpenSSF OpenBao Transit engine

The dns and http methods need a private key for in-process signing, given as
--private-key <hex>, --private-key-file <path> or the MCP_PRIVATE_KEY env var.
--private-key and --private-key-file are mutually exclusive; either one
overrides MCP_PRIVATE_KEY. For out-of-process
signing, use the openbao signing provider. Signing is needed for an
authentication challenge with the registry.

Examples:

  # Interactive Keycloak login, using RFC 8628 device flow
  mcp-publisher login keycloak --issuer https://auth.codeslice.dev/realms/codeslice --client-id codeslice-publisher

  # Sign in using OpenBao Transit for DNS authentication
  mcp-publisher login dns openbao --domain example.com --openbao-addr http://openbao.security.svc:8200 --openbao-key publisher-signer

  # Sign in using a specific Ed25519 private key for DNS authentication
  # Sign in using a specific Ed25519 private key for DNS authentication
  mcp-publisher login dns -algorithm ed25519 -domain example.com -private-key <64 hex chars>

  # Sign in using a specific ECDSA P-384 private key for DNS authentication
  mcp-publisher login dns -algorithm ecdsap384 -domain example.com -private-key <96 hex chars>

  # Keep the key out of the command line: read it from a file or the environment
  mcp-publisher login dns -domain example.com -private-key-file key.hex
  MCP_PRIVATE_KEY=<64 hex chars> mcp-publisher login dns -domain example.com
`)
	}

	method := args[0]
	flags, err := parseLoginFlags(method, args)
	if err != nil {
		return err
	}

	var signer auth.Signer
	if flags.SignerType != NoSignerType {
		signer, err = createSigner(flags)
		if err != nil {
			return err
		}
	}

	authProvider, err := createAuthProvider(method, flags.RegistryURL, flags.Domain, flags, signer)
	if err != nil {
		return err
	}
	ctx := context.Background()
	_, _ = fmt.Fprintf(os.Stdout, "Logging in with %s...\n", method)

	if err := authProvider.Login(ctx); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	token, err := authProvider.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if err := ensureTokenDir(); err != nil {
		return err
	}

	tokenPath, err := tokenFilePath()
	if err != nil {
		return err
	}

	tokenData := map[string]string{
		"token":    token,
		"method":   method,
		"registry": flags.RegistryURL,
	}

	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	if err := os.WriteFile(tokenPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	_, _ = fmt.Fprintln(os.Stdout, "✓ Successfully logged in")
	return nil
}
