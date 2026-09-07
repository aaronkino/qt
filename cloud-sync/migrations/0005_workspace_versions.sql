CREATE TABLE IF NOT EXISTS cloud_workspace_versions (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source TEXT NOT NULL,
  project_count INTEGER NOT NULL DEFAULT 0,
  template_count INTEGER NOT NULL DEFAULT 0,
  category_count INTEGER NOT NULL DEFAULT 0,
  clause_count INTEGER NOT NULL DEFAULT 0,
  byte_size INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cloud_workspace_versions_recent
ON cloud_workspace_versions(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cloud_workspace_version_records (
  version_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (version_id, entity_type, entity_id),
  FOREIGN KEY (version_id) REFERENCES cloud_workspace_versions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cloud_workspace_version_records_lookup
ON cloud_workspace_version_records(version_id, entity_type);
