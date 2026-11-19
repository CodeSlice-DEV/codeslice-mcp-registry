# MCP Registry Deployment & Infrastructure

This directory contains cloud-sovereign infrastructure as code and deployment charts for the MCP Registry service.

## Architecture

- **OpenTofu (`deploy/opentofu/`):** Enterprise-grade OpenTofu modules managing Kubernetes resources, HA PostgreSQL (CloudNativePG), Apache Ozone S3 object storage credentials, Envoy Gateway API ingress, cert-manager TLS issuance, Perses dashboards, and K8up automated backups.
- **Helm (`deploy/helm/mcp-registry/`):** Cloud-native Helm chart deploying the stateless MCP Registry API service with native Gateway API `HTTPRoute` integration, strict OpenID Connect configuration (Keycloak), and zero unpinned dependencies.

## Structure

```
deploy/
├── helm/
│   └── mcp-registry/          # Helm chart for MCP Registry
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── deployment.yaml
│           ├── service.yaml
│           ├── serviceaccount.yaml
│           ├── configmap.yaml
│           └── httproute.yaml
├── opentofu/                  # OpenTofu infrastructure modules
│   ├── versions.tf            # Provider pins (>= 1.8.0, kubernetes, helm)
│   ├── variables.tf           # Environment parameters
│   ├── main.tf                # Namespace definitions
│   ├── cloudnativepg.tf       # HA 3-node PostgreSQL cluster with Ozone WAL archiving
│   ├── ozone.tf               # Apache Ozone S3 Gateway credentials
│   ├── gateway.tf             # Gateway API Gateway (Envoy Gateway eg)
│   ├── cert_manager.tf        # ClusterIssuer & Let's Encrypt / self-signed TLS
│   ├── monitoring.tf          # Perses dashboard deployment with OIDC
│   ├── backup.tf              # K8up automated backup Schedule to Ozone S3
│   ├── registry.tf            # Helm release instantiation of mcp-registry
│   └── outputs.tf             # Registry URL, database host, gateway IP
└── README.md
```

## Quick Start

### 1. Helm Chart Validation

```bash
helm lint deploy/helm/mcp-registry
helm template mcp-registry deploy/helm/mcp-registry
```

### 2. OpenTofu Validation and Deployment

```bash
cd deploy/opentofu
tofu fmt -check
tofu init
tofu plan -out=tfplan
tofu apply tfplan
```

### 3. Verification

Once deployed, query the service status via the Envoy Gateway HTTPRoute:

```bash
curl -k https://<GATEWAY-IP>/v0/ping
```
