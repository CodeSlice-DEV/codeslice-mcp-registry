# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# CNCF CloudNativePG Highly Available Cluster
# Replaces unmanaged PostgreSQL with enterprise HA CloudNativePG operator

resource "kubernetes_manifest" "cloudnativepg_cluster" {
  manifest = {
    apiVersion = "postgresql.cnpg.io/v1"
    kind       = "Cluster"
    metadata = {
      name      = "mcp-registry-postgresql"
      namespace = kubernetes_namespace.mcp_system.metadata[0].name
      labels = {
        "app.kubernetes.io/name"       = "cloudnativepg"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      instances             = 3
      primaryUpdateStrategy = "unsupervised"

      storage = {
        size         = "20Gi"
        storageClass = var.storage_class
      }

      monitoring = {
        enablePodMonitor = true
      }

      backup = {
        barmanObjectStore = {
          destinationPath = "s3://${var.ozone_s3_bucket}/cnpg-wal/"
          endpointURL     = var.ozone_s3_endpoint
          s3Credentials = {
            inheritFromIAMRole = false
          }
          wal = {
            compression = "gzip"
            maxParallel = 4
          }
        }
      }

      bootstrap = {
        initdb = {
          database = "mcp-registry"
          owner    = "mcpregistry"
          secret = {
            name = "mcp-registry-db-credentials"
          }
        }
      }
    }
  }
}
