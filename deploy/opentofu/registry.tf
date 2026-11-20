# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# Deploy the MCP Registry Helm Chart

resource "helm_release" "mcp_registry" {
  name       = "mcp-registry"
  namespace  = kubernetes_namespace.mcp_system.metadata[0].name
  chart      = "${path.module}/../helm/mcp-registry"
  depends_on = [kubernetes_namespace.mcp_system]

  set {
    name  = "replicaCount"
    value = var.replica_count
  }

  set {
    name  = "gateway.hostname"
    value = var.domain_name
  }

  set {
    name  = "oidc.issuer"
    value = var.keycloak_issuer
  }

  set {
    name  = "oidc.clientID"
    value = var.keycloak_client_id
  }
}
