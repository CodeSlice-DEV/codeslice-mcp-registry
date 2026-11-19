# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# CNCF K8up Backup Schedule with Apache Ozone S3
# Replaces hardcoded passwords with OpenBao / ESO secret references

resource "kubernetes_manifest" "k8up_schedule" {
  manifest = {
    apiVersion = "k8up.io/v1"
    kind       = "Schedule"
    metadata = {
      name      = "mcp-registry-backup-schedule"
      namespace = kubernetes_namespace.mcp_system.metadata[0].name
      labels = {
        "app.kubernetes.io/name"       = "k8up"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      backup = {
        schedule                   = "0 3 * * *"
        failedJobsHistoryLimit     = 3
        successfulJobsHistoryLimit = 3
      }
      check = {
        schedule = "0 5 * * 0"
      }
      prune = {
        schedule = "0 4 * * 0"
        retention = {
          keepDaily   = 7
          keepWeekly  = 4
          keepMonthly = 6
        }
      }
      backend = {
        s3 = {
          endpoint = var.ozone_s3_endpoint
          bucket   = var.ozone_s3_bucket
        }
        repoPasswordSecretRef = {
          name = "ozone-s3-credentials"
          key  = "password"
        }
      }
    }
  }
}
