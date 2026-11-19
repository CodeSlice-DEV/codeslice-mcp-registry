# Copyright (c) CODESLICE IT SOLUTIONS PRIVATE LIMITED.
# SPDX-License-Identifier: LicenseRef-Prosperity-3.0.0

# CNCF Perses + Prometheus + OpenTelemetry Collector Monitoring
# Replaces AGPLv3 Grafana and VictoriaMetrics with Apache-2.0 CNCF Perses

resource "kubernetes_manifest" "perses_deployment" {
  manifest = {
    apiVersion = "apps/v1"
    kind       = "Deployment"
    metadata = {
      name      = "perses"
      namespace = kubernetes_namespace.mcp_system.metadata[0].name
      labels = {
        "app.kubernetes.io/name"       = "perses"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      replicas = 1
      selector = {
        matchLabels = {
          "app.kubernetes.io/name" = "perses"
        }
      }
      template = {
        metadata = {
          labels = {
            "app.kubernetes.io/name" = "perses"
          }
        }
        spec = {
          securityContext = {
            runAsNonRoot = true
            runAsUser    = 65534
          }
          containers = [
            {
              name  = "perses"
              image = "persesdev/perses:v0.49.0@sha256:0633b49c063cf4eb178b54dbfb5142be81682885970c322744883196a5ca8e21"
              ports = [
                {
                  containerPort = 8080
                  name          = "http"
                }
              ]
              env = [
                {
                  name  = "PERSES_OIDC_ISSUER"
                  value = var.keycloak_issuer
                },
                {
                  name  = "PERSES_OIDC_CLIENT_ID"
                  value = var.keycloak_client_id
                }
              ]
              resources = {
                limits = {
                  cpu    = "500m"
                  memory = "512Mi"
                }
                requests = {
                  cpu    = "50m"
                  memory = "64Mi"
                }
              }
            }
          ]
        }
      }
    }
  }
}

resource "kubernetes_manifest" "otel_collector" {
  manifest = {
    apiVersion = "apps/v1"
    kind       = "Deployment"
    metadata = {
      name      = "otel-collector"
      namespace = kubernetes_namespace.mcp_system.metadata[0].name
      labels = {
        "app.kubernetes.io/name"       = "otel-collector"
        "app.kubernetes.io/part-of"    = "codeslice-platform"
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      replicas = 1
      selector = {
        matchLabels = {
          "app.kubernetes.io/name" = "otel-collector"
        }
      }
      template = {
        metadata = {
          labels = {
            "app.kubernetes.io/name" = "otel-collector"
          }
        }
        spec = {
          securityContext = {
            runAsNonRoot = true
            runAsUser    = 65534
          }
          containers = [
            {
              name  = "otel-collector"
              image = "otel/opentelemetry-collector-contrib:0.119.0@sha256:f1262d499318a8b8a5fcb81f18579cfebce290eb38df72c388ee0cb6532ae152"
              ports = [
                {
                  containerPort = 4317
                  name          = "otlp-grpc"
                },
                {
                  containerPort = 4318
                  name          = "otlp-http"
                },
                {
                  containerPort = 8889
                  name          = "prometheus"
                }
              ]
              resources = {
                limits = {
                  cpu    = "500m"
                  memory = "512Mi"
                }
                requests = {
                  cpu    = "100m"
                  memory = "128Mi"
                }
              }
            }
          ]
        }
      }
    }
  }
}
