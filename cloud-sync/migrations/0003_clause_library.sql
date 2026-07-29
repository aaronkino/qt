CREATE TABLE IF NOT EXISTS cloud_clauses (
  workspace_id TEXT NOT NULL,
  id TEXT NOT NULL,
  category TEXT NOT NULL,
  clause_text TEXT NOT NULL,
  severity INTEGER NOT NULL DEFAULT 2,
  sort_order INTEGER NOT NULL DEFAULT 0,
  is_core INTEGER NOT NULL DEFAULT 0,
  core_order INTEGER,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_clauses_order
ON cloud_clauses(workspace_id, category, severity, sort_order);

CREATE TABLE IF NOT EXISTS cloud_workspace_state (
  workspace_id TEXT PRIMARY KEY,
  clause_library_initialized INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
