ALTER TABLE cloud_stamp_asset_versions
ADD COLUMN crop_enabled INTEGER NOT NULL DEFAULT 0;

ALTER TABLE cloud_stamp_asset_versions
ADD COLUMN default_width_mm REAL NOT NULL DEFAULT 18;

ALTER TABLE cloud_stamp_asset_versions
ADD COLUMN default_height_mm REAL NOT NULL DEFAULT 18;

ALTER TABLE cloud_stamp_asset_versions
ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
