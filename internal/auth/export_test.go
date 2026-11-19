package auth

// Export internal helpers for external auth_test package testing (#2112)
func (j *JWTManager) IsIssuerAllowedForTest(issuer string) bool {
	return j.isIssuerAllowed(issuer)
}

func (j *JWTManager) IsTenantAllowedForTest(tenantID string) bool {
	return j.isTenantAllowed(tenantID)
}
