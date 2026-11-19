# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# Kubernetes Gateway API + CNCF Envoy Gateway
# Replaces maintenance-mode ingress-nginx with standard Gateway API

resource "kubernetes_manifest" "envoy_gateway" {
  manifest = {
    apiVersion = "gateway.networking.k8s.io/v1"
    kind       = "Gateway"
    metadata = {
      name      = "envoy-gateway"
      namespace = kubernetes_namespace.mcp_system.metadata[0].name
      labels = {
        "app.kubernetes.io/name"       = "envoy-gateway"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      gatewayClassName = "eg"
      listeners = [
        {
          name     = "http"
          protocol = "HTTP"
          port     = 80
          allowedRoutes = {
            namespaces = {
              from = "Same"
            }
          }
        },
        {
          name     = "https"
          protocol = "HTTPS"
          port     = 443
          hostname = var.domain_name
          tls = {
            mode = "Terminate"
            certificateRefs = [
              {
                name = "mcp-registry-tls"
              }
            ]
          }
          allowedRoutes = {
            namespaces = {
              from = "Same"
            }
          }
        }
      ]
    }
  }
}
