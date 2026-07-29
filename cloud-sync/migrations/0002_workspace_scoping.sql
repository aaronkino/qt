CREATE TABLE IF NOT EXISTS cloud_projects (
  workspace_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_projects_updated_at
ON cloud_projects(workspace_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS cloud_contract_templates (
  workspace_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  notes_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_contract_templates_updated_at
ON cloud_contract_templates(workspace_id, updated_at DESC);
