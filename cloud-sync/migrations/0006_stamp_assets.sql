CREATE TABLE IF NOT EXISTS cloud_stamp_assets (
  workspace_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  current_version_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_stamp_assets_active
ON cloud_stamp_assets(workspace_id, deleted_at, updated_at DESC);

CREATE TABLE IF NOT EXISTS cloud_stamp_asset_versions (
  workspace_id TEXT NOT NULL,
  id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL,
  byte_size INTEGER NOT NULL DEFAULT 0,
  original_width_px INTEGER NOT NULL DEFAULT 0,
  original_height_px INTEGER NOT NULL DEFAULT 0,
  aspect_ratio REAL NOT NULL DEFAULT 1,
  crop_json TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_stamp_asset_versions_asset
ON cloud_stamp_asset_versions(workspace_id, asset_id, created_at DESC);

ALTER TABLE cloud_workspace_versions
ADD COLUMN stamp_asset_count INTEGER NOT NULL DEFAULT 0;
