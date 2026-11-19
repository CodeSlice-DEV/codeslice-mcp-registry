package registries

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	ErrAirgapPublicRegistryForbidden = errors.New("public registry is forbidden in air-gap mode")
	ErrDummyDigestDetected           = errors.New("placeholder or dummy hash detected")
	ErrRepoNameMismatch              = errors.New("repository path does not match server name")

	hex64Regex = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Known dummy / placeholder SHA-256 digests that must be rejected.
var knownDummyDigests = map[string]string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":  "sha256(\"\") empty string hash",
	"ca978112ca1bbdcafac231b39a23dc4da78608149614097b6004fb68640fa67e":  "sha256(\"a\") single character hash",
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":  "sha256(\"abc\") test hash",
	"c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd47": "sha256(\"admin\") placeholder hash",
	"0000000000000000000000000000000000000000000000000000000000000000":  "all zeroes placeholder",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff":  "all f placeholder",
}

// IsAirgapModeEnabled checks if sovereign air-gap isolation mode is enabled.
func IsAirgapModeEnabled() bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv("MCP_REGISTRY_AIRGAP_MODE")))
	if val == "" {
		val = strings.ToLower(strings.TrimSpace(os.Getenv("AIRGAP_MODE")))
	}
	return val == "true" || val == "1" || val == "yes"
}

// IsPublicOCIRegistry checks if the given OCI registry domain is a public registry.
func IsPublicOCIRegistry(registry string) bool {
	return registry == "docker.io" ||
		registry == "registry-1.docker.io" ||
		registry == "index.docker.io" ||
		registry == "ghcr.io" ||
		registry == "quay.io" ||
		registry == "mcr.microsoft.com"
}

// IsPrivateEnterpriseRegistry checks if the registry belongs to approved private cloud registries.
func IsPrivateEnterpriseRegistry(registry string) bool {
	// Google Artifact Registry (*.pkg.dev)
	if strings.HasSuffix(registry, ".pkg.dev") {
		return true
	}
	// Azure Container Registry (*.azurecr.io)
	if strings.HasSuffix(registry, ".azurecr.io") {
		return true
	}
	// AWS Elastic Container Registry (*.dkr.ecr.*.amazonaws.com or *.amazonaws.com)
	if strings.Contains(registry, ".dkr.ecr.") && strings.HasSuffix(registry, ".amazonaws.com") {
		return true
	}

	// Custom private OCI registries
	if custom := os.Getenv("MCP_REGISTRY_ALLOWED_OCI_REGISTRIES"); custom != "" {
		for _, r := range strings.Split(custom, ",") {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			if r == "*" || r == registry {
				return true
			}
			if strings.HasPrefix(r, "*.") && strings.HasSuffix(registry, strings.TrimPrefix(r, "*")) {
				return true
			}
		}
	}

	return false
}

// ValidateDigestFormatAndNonDummy validates that the digest is a valid 64-hex SHA-256 and not a dummy hash.
func ValidateDigestFormatAndNonDummy(digestHex string) error {
	digestHex = strings.ToLower(strings.TrimSpace(digestHex))
	if !hex64Regex.MatchString(digestHex) {
		return fmt.Errorf("invalid digest format: expected 64 lowercase hexadecimal characters, got '%s'", digestHex)
	}

	if reason, dummy := knownDummyDigests[digestHex]; dummy {
		return fmt.Errorf("%w: %s (%s)", ErrDummyDigestDetected, digestHex, reason)
	}

	// Reject all-identical repeated characters (e.g. 111111... or 222222...)
	allIdentical := true
	for i := 1; i < len(digestHex); i++ {
		if digestHex[i] != digestHex[0] {
			allIdentical = false
			break
		}
	}
	if allIdentical {
		return fmt.Errorf("%w: repeated character placeholder '%s'", ErrDummyDigestDetected, digestHex)
	}

	return nil
}

// ValidateServerNameRepositoryAlignment verifies that an OCI repository path aligns with the server name.
func ValidateServerNameRepositoryAlignment(repoStr, serverName string) error {
	if serverName == "" {
		return nil
	}

	parts := strings.Split(serverName, "/")
	if len(parts) != 2 {
		return nil
	}

	serverBaseName := parts[1]
	nameCore := strings.TrimSuffix(serverBaseName, "-mcp")

	repoLower := strings.ToLower(repoStr)
	baseLower := strings.ToLower(serverBaseName)
	coreLower := strings.ToLower(nameCore)

	// Repo must contain the base server name or core server name, or vice versa
	if strings.Contains(repoLower, coreLower) || strings.Contains(repoLower, baseLower) ||
		strings.Contains(coreLower, repoLower) || strings.Contains(baseLower, repoLower) {
		return nil
	}

	// Also allow full namespace/name match if repo contains it
	if strings.Contains(repoLower, strings.ToLower(serverName)) {
		return nil
	}

	return fmt.Errorf("%w: repository '%s' must align with server name '%s'", ErrRepoNameMismatch, repoStr, serverName)
}
