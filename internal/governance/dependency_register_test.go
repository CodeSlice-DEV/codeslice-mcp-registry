// Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
// SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

package governance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

type DependencyRegister struct {
	Metadata struct {
		SchemaVersion string `yaml:"schema_version"`
		Issue         int    `yaml:"issue"`
		Rule          string `yaml:"rule"`
	} `yaml:"metadata"`
	Packages map[string]struct {
		Scope      string   `yaml:"scope"`
		Scopes     []string `yaml:"scopes"`
		License    string   `yaml:"license"`
		Governance string   `yaml:"governance"`
		Maturity   string   `yaml:"maturity"`
		Decision   string   `yaml:"decision"`
		Exception  bool     `yaml:"exception"`
		Rationale  string   `yaml:"rationale"`
	} `yaml:"packages"`
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", dir)
		}
		dir = parent
	}
}

func TestRule22_DependencyRegister_ZeroDisallowedModules(t *testing.T) {
	root := findRepoRoot(t)
	goModData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	require.NoError(t, err)

	mf, err := modfile.Parse("go.mod", goModData, nil)
	require.NoError(t, err)

	disallowedPrefixes := []string{
		"cloud.google.com/go/kms",
		"github.com/Azure/azure-sdk-for-go",
		"github.com/AzureAD/microsoft-authentication-library-for-go",
		"github.com/pulumi",
	}

	for _, req := range mf.Require {
		for _, disallowed := range disallowedPrefixes {
			assert.False(t, strings.HasPrefix(req.Mod.Path, disallowed),
				"Rule 22 violation: module %s matches disallowed prefix %s", req.Mod.Path, disallowed)
		}
	}
}

func TestRule22_DependencyRegister_BijectiveParity(t *testing.T) {
	root := findRepoRoot(t)

	// Read go.mod
	goModData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	require.NoError(t, err)

	mf, err := modfile.Parse("go.mod", goModData, nil)
	require.NoError(t, err)

	// Read dependency_register.toml (parseable as YAML/TOML subsets)
	registerData, err := os.ReadFile(filepath.Join(root, "docs", "decisions", "dependency_register.toml"))
	require.NoError(t, err)

	// Simple TOML table parser for [packages."pkg"]
	registerPackages := make(map[string]bool)
	lines := strings.Split(string(registerData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[packages.\"") && strings.HasSuffix(line, "\"]") {
			pkg := strings.TrimSuffix(strings.TrimPrefix(line, "[packages.\""), "\"]")
			registerPackages[pkg] = true
		}
	}

	require.NotEmpty(t, registerPackages, "register must contain packages")

	// Verify all direct dependencies in go.mod are registered
	for _, req := range mf.Require {
		if !req.Indirect {
			assert.True(t, registerPackages[req.Mod.Path],
				"Rule 22 violation: direct dependency %s is missing from dependency_register.toml", req.Mod.Path)
		}
	}
}

func TestRule22_ZeroVendorBypassesAndZeroCloudKMSSDKs(t *testing.T) {
	root := findRepoRoot(t)

	// Scan all go files under internal/ and cmd/
	for _, subDir := range []string{"internal", "cmd"} {
		dirPath := filepath.Join(root, subDir)
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			require.NoError(t, err)
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			content, err := os.ReadFile(path) //nolint:gosec // Test governance scan
			require.NoError(t, err)
			contentStr := string(content)

			assert.False(t, strings.Contains(contentStr, "SkipIssuerCheck: true"),
				"Security bypass violation: found SkipIssuerCheck: true in %s", path)

			assert.False(t, strings.Contains(contentStr, "cmd/publisher/auth/googlekms"),
				"Purged package reference violation: found googlekms import in %s", path)

			assert.False(t, strings.Contains(contentStr, "cmd/publisher/auth/azurekeyvault"),
				"Purged package reference violation: found azurekeyvault import in %s", path)

			return nil
		})
		require.NoError(t, err)
	}
}
