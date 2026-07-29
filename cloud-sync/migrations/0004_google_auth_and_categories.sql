ALTER TABLE cloud_workspace_state
ADD COLUMN clause_categories_initialized INTEGER NOT NULL DEFAULT 0;

ALTER TABLE cloud_clauses
ADD COLUMN category_id TEXT;

CREATE TABLE IF NOT EXISTS cloud_clause_categories (
  workspace_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_cloud_clause_categories_order
ON cloud_clause_categories(workspace_id, sort_order, name);

INSERT OR IGNORE INTO cloud_clause_categories
  (workspace_id, id, name, sort_order, updated_at)
SELECT
  workspace_id,
  'legacy-' || lower(hex(randomblob(12))),
  category,
  MIN(sort_order),
  MAX(updated_at)
FROM cloud_clauses
GROUP BY workspace_id, category;

UPDATE cloud_clauses
SET category_id = (
  SELECT cloud_clause_categories.id
  FROM cloud_clause_categories
  WHERE cloud_clause_categories.workspace_id = cloud_clauses.workspace_id
    AND cloud_clause_categories.name = cloud_clauses.category
  LIMIT 1
)
WHERE category_id IS NULL;

UPDATE cloud_workspace_state
SET clause_categories_initialized = 1
WHERE EXISTS (
  SELECT 1
  FROM cloud_clause_categories
  WHERE cloud_clause_categories.workspace_id =
    cloud_workspace_state.workspace_id
);

CREATE TABLE IF NOT EXISTS cloud_users (
  id TEXT PRIMARY KEY,
  google_sub TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  display_name TEXT NOT NULL,
  picture_url TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES cloud_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cloud_sessions_user
ON cloud_sessions(user_id, expires_at);
