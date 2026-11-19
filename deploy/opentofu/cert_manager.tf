# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# CNCF cert-manager Automated TLS Certificate Lifecycle

resource "kubernetes_manifest" "cluster_issuer" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind       = "ClusterIssuer"
    metadata = {
      name = "letsencrypt-${var.environment}"
      labels = {
        "app.kubernetes.io/name"       = "cert-manager"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      acme = {
        server = var.environment == "production" ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory"
        email  = "security@codeslice.dev"
        privateKeySecretRef = {
          name = "letsencrypt-${var.environment}-private-key"
        }
        solvers = [
          {
            http01 = {
              gatewayHTTPRoute = {
                parentRefs = [
                  {
                    name      = "envoy-gateway"
                    namespace = kubernetes_namespace.mcp_system.metadata[0].name
                  }
                ]
              }
            }
          }
        ]
      }
    }
  }
}

resource "kubernetes_manifest" "tls_certificate" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata = {
      name      = "mcp-registry-tls"
      namespace = kubernetes_namespace.mcp_system.metadata[0].name
      labels = {
        "app.kubernetes.io/name"       = "mcp-registry-tls"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      secretName = "mcp-registry-tls"
      issuerRef = {
        name = "letsencrypt-${var.environment}"
        kind = "ClusterIssuer"
      }
      dnsNames = [
        var.domain_name
      ]
    }
  }
}
