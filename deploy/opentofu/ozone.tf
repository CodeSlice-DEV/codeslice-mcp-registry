# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# Apache Ozone S3 Gateway Sovereign Object Storage Configuration
# Replaces legacy AGPLv3 MinIO with enterprise ASF Apache Ozone

resource "kubernetes_secret" "ozone_s3_credentials" {
  metadata {
    name      = "ozone-s3-credentials"
    namespace = kubernetes_namespace.mcp_system.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = "ozone-credentials"
      "app.kubernetes.io/part-of"    = "codeslice-platform"
      "app.kubernetes.io/managed-by" = "opentofu"
    }
  }

  # Managed dynamically via OpenBao / External Secrets Operator
  data = {
    s3_endpoint = var.ozone_s3_endpoint
    s3_bucket   = var.ozone_s3_bucket
  }

  lifecycle {
    ignore_changes = [data]
  }
}
