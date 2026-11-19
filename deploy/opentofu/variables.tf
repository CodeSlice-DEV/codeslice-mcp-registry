# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

variable "namespace" {
  description = "Kubernetes namespace for the MCP registry components"
  type        = string
  default     = "mcp-system"
}

variable "domain_name" {
  description = "Public domain name for the MCP registry"
  type        = string
  default     = "registry.codeslice.dev"
}

variable "environment" {
  description = "Deployment environment (staging or production)"
  type        = string
  default     = "production"
}

variable "storage_class" {
  description = "Storage class name for persistent volumes"
  type        = string
  default     = "standard"
}

variable "ozone_s3_endpoint" {
  description = "Apache Ozone S3 Gateway endpoint for sovereign object storage"
  type        = string
  default     = "http://ozone-s3.storage.svc:9878"
}

variable "ozone_s3_bucket" {
  description = "Apache Ozone S3 bucket name for backups and WAL archiving"
  type        = string
  default     = "mcp-registry-backups"
}

variable "keycloak_issuer" {
  description = "Keycloak OIDC realm issuer URL"
  type        = string
  default     = "https://auth.codeslice.dev/realms/codeslice"
}

variable "keycloak_client_id" {
  description = "Keycloak OIDC client ID for MCP registry"
  type        = string
  default     = "codeslice-registry"
}

variable "openbao_addr" {
  description = "OpenSSF OpenBao transit and secrets address"
  type        = string
  default     = "http://openbao.security.svc:8200"
}

variable "replica_count" {
  description = "Replica count for the MCP registry deployment"
  type        = number
  default     = 2
}
