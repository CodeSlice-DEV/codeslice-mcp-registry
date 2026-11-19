# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

resource "kubernetes_namespace" "mcp_system" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "mcp-system"
      "app.kubernetes.io/part-of"    = "codeslice-platform"
      "app.kubernetes.io/managed-by" = "opentofu"
    }
  }
}
