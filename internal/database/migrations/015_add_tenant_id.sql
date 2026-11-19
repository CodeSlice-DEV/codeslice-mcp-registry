-- Add tenant_id column and index to support multi-tenant isolation (#2112)

ALTER TABLE servers ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_servers_tenant_id ON servers (tenant_id);
