# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

output "registry_url" {
  description = "Public URL for the MCP Registry"
  value       = "https://${var.domain_name}"
}

output "namespace" {
  description = "Kubernetes namespace where MCP registry is deployed"
  value       = kubernetes_namespace.mcp_system.metadata[0].name
}

output "database_host" {
  description = "CloudNativePG cluster read-write service hostname"
  value       = "mcp-registry-postgresql-rw.${var.namespace}.svc.cluster.local"
}

output "backup_ozone_bucket" {
  description = "Apache Ozone S3 bucket used for backups"
  value       = var.ozone_s3_bucket
}
