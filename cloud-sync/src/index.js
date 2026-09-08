import { createRemoteJWKSet, jwtVerify } from "jose";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_STAMP_BYTES = 8 * 1024 * 1024;
const STAMP_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
const SESSION_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const GOOGLE_JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);

class ApiError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });

const getCorsHeaders = (request, env) => {
  const origin = request.headers.get("origin") || "";
  const allowedOrigins = String(env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  if (!allowedOrigins.includes(origin)) return {};

  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,PUT,POST,DELETE,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
};

const sha256 = async (value) => {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
};

const randomToken = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
};

const getBearerToken = (request) => {
  const header = request.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  return token.length >= 20 && token.length <= 500 ? token : "";
};

const getAuthContext = async (request, env) => {
  const token = getBearerToken(request);
  if (!token) return null;

  const tokenHash = await sha256(token);
  const session = await env.DB.prepare(
    `SELECT
       s.user_id,
       s.expires_at,
       u.email,
       u.display_name,
       u.picture_url
     FROM cloud_sessions s
     JOIN cloud_users u ON u.id = s.user_id
     WHERE s.token_hash = ?1 AND s.expires_at > ?2
     LIMIT 1`,
  ).bind(tokenHash, new Date().toISOString()).first();

  if (session) {
    return {
      type: "google",
      tokenHash,
      workspaceId: `user:${session.user_id}`,
      user: {
        id: session.user_id,
        email: session.email,
        name: session.display_name,
        picture: session.picture_url,
      },
      expiresAt: session.expires_at,
    };
  }

  // Backward compatibility: existing manually generated sync keys continue to
  // resolve to their original SHA-256 workspace.
  return {
    type: "key",
    tokenHash,
    workspaceId: tokenHash,
    user: null,
    expiresAt: null,
  };
};

const readJson = async (request) => {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_BODY_BYTES) throw new ApiError("PAYLOAD_TOO_LARGE", 413);
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) {
    throw new ApiError("PAYLOAD_TOO_LARGE", 413);
  }
  try {
    return JSON.parse(text || "{}");
  } catch {
    throw new ApiError("JSON 格式不正確");
  }
};

const validId = (value) =>
  typeof value === "string" && value.length > 0 && value.length <= 160;

const validName = (value) =>
  typeof value === "string" && value.trim().length > 0 && value.trim().length <= 200;

const normalizeUpdatedAt = (value) => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    ? new Date(parsed).toISOString()
    : new Date().toISOString();
};

const mapProject = (row) => ({
  id: row.id,
  name: row.name,
  updatedAt: row.updated_at,
  data: JSON.parse(row.data_json),
});

const mapTemplate = (row) => ({
  id: row.id,
  name: row.name,
  updatedAt: row.updated_at,
  notes: JSON.parse(row.notes_json),
});

const mapCategory = (row) => ({
  id: row.id,
  name: row.name,
  sortOrder: Number(row.sort_order),
  updatedAt: row.updated_at,
});

const mapClause = (row) => ({
  id: row.id,
  categoryId: row.category_id || "",
  category: row.category,
  text: row.clause_text,
  severity: Number(row.severity),
  sortOrder: Number(row.sort_order),
  isCore: Boolean(row.is_core),
  coreOrder: row.core_order == null ? null : Number(row.core_order),
  updatedAt: row.updated_at,
});

const parseCropJson = value => {
  if (!value) return null;
  try {
    const crop = JSON.parse(value);
    if (!crop || typeof crop !== "object") return null;
    return crop;
  } catch {
    return null;
  }
};

const mapStampAsset = row => ({
  id: row.id,
  name: row.name,
  cloudName: row.name,
  versionId: row.version_id || "",
  mimeType: row.mime_type || "",
  originalWidthPx: Number(row.original_width_px || 0),
  originalHeightPx: Number(row.original_height_px || 0),
  aspectRatio: Number(row.aspect_ratio || 1),
  cropEnabled: Boolean(row.crop_enabled),
  crop: parseCropJson(row.crop_json),
  defaultWidthMm: Number(row.default_width_mm || 18),
  defaultHeightMm: Number(row.default_height_mm || 18),
  schemaVersion: Number(row.schema_version || 1),
  updatedAt: row.updated_at || row.version_created_at || "",
  cloudState: "synced",
});

const validStampName = value =>
  typeof value === "string" && value.trim().length > 0 && value.trim().length <= 200;

const validStampId = value =>
  typeof value === "string" && /^stamp_[A-Za-z0-9_-]{8,80}$/.test(value);

const getStampRows = (env, workspaceId) => env.DB.prepare(
  `SELECT
     a.id, a.name, a.updated_at,
     v.id version_id, v.mime_type, v.original_width_px,
     v.original_height_px, v.aspect_ratio, v.crop_enabled, v.crop_json,
     v.default_width_mm, v.default_height_mm, v.schema_version,
     v.created_at version_created_at
   FROM cloud_stamp_assets a
   LEFT JOIN cloud_stamp_asset_versions v
     ON v.workspace_id = a.workspace_id AND v.id = a.current_version_id
   WHERE a.workspace_id = ?1 AND a.deleted_at IS NULL
   ORDER BY a.updated_at DESC, a.name COLLATE NOCASE`,
).bind(workspaceId);

const getStampVersion = async (env, workspaceId, assetId, versionId = "") => {
  const row = await env.DB.prepare(
    `SELECT a.id asset_id, a.name, a.deleted_at,
            v.id version_id, v.object_key, v.mime_type, v.byte_size,
            v.original_width_px, v.original_height_px, v.aspect_ratio,
            v.crop_json
     FROM cloud_stamp_assets a
     JOIN cloud_stamp_asset_versions v
       ON v.workspace_id = a.workspace_id AND v.asset_id = a.id
     WHERE a.workspace_id = ?1
       AND a.id = ?2
       AND (?3 = '' OR v.id = ?3)
     ORDER BY CASE WHEN v.id = a.current_version_id THEN 0 ELSE 1 END,
              v.created_at DESC
     LIMIT 1`,
  ).bind(workspaceId, assetId, versionId).first();
  if (!row) throw new ApiError("找不到印章資產", 404);
  return row;
};

const readStampFormUpload = async request => {
  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file.arrayBuffer !== "function") {
    throw new ApiError("缺少印章圖片檔");
  }
  const contentType = String(file.type || "").split(";")[0].toLowerCase();
  if (!STAMP_MIME_TYPES.has(contentType)) throw new ApiError("印章格式僅支援 PNG、JPEG、WebP 或 GIF");
  if (Number(file.size || 0) > MAX_STAMP_BYTES) throw new ApiError("印章圖片不可超過 8 MB", 413);
  const bytes = await file.arrayBuffer();
  if (bytes.byteLength > MAX_STAMP_BYTES) throw new ApiError("印章圖片不可超過 8 MB", 413);
  const name = String(form.get("name") || file.name || "未命名印章").trim().slice(0, 200) || "未命名印章";
  const originalWidthPx = Math.max(0, Math.trunc(Number(form.get("originalWidthPx") || 0)));
  const originalHeightPx = Math.max(0, Math.trunc(Number(form.get("originalHeightPx") || 0)));
  const aspectRatio = Number(form.get("aspectRatio") || 1);
  const cropEnabled = ["1", "true", "on"].includes(String(form.get("cropEnabled") || "").toLowerCase());
  const requestedDefaultWidthMm = Number(form.get("defaultWidthMm"));
  const requestedDefaultHeightMm = Number(form.get("defaultHeightMm"));
  const requestedSchemaVersion = Number(form.get("schemaVersion"));
  const defaultWidthMm = Number.isFinite(requestedDefaultWidthMm) ? Math.min(120, Math.max(1, requestedDefaultWidthMm)) : 18;
  const defaultHeightMm = Number.isFinite(requestedDefaultHeightMm) ? Math.min(120, Math.max(1, requestedDefaultHeightMm)) : 18;
  const schemaVersion = Number.isFinite(requestedSchemaVersion) ? Math.min(10, Math.max(1, Math.trunc(requestedSchemaVersion))) : 1;
  let cropJson = null;
  try {
    const crop = JSON.parse(String(form.get("crop") || "null"));
    if (crop && typeof crop === "object") cropJson = JSON.stringify(crop);
  } catch {
    cropJson = null;
  }
  return { name, contentType, bytes, originalWidthPx, originalHeightPx, aspectRatio: Number.isFinite(aspectRatio) && aspectRatio > 0 ? aspectRatio : 1, cropEnabled, cropJson, defaultWidthMm, defaultHeightMm, schemaVersion };
};

const requireStampBucket = env => {
  if (!env.STAMP_BUCKET) throw new ApiError("印章儲存尚未完成 R2 bucket 設定", 503);
  return env.STAMP_BUCKET;
};

const createStampAsset = async (env, workspaceId, upload) => {
  const assetId = `stamp_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  const versionId = `stampv_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  const objectKey = stampObjectKey(workspaceId, assetId, versionId, upload.contentType);
  const now = new Date().toISOString();
  const bucket = requireStampBucket(env);
  await bucket.put(objectKey, upload.bytes, {
    httpMetadata: { contentType: upload.contentType, cacheControl: "private, no-store" },
    customMetadata: { workspaceId, assetId, versionId },
  });
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cloud_stamp_assets
         (workspace_id, id, name, current_version_id, created_at, updated_at, deleted_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)`,
    ).bind(workspaceId, assetId, upload.name, versionId, now),
    env.DB.prepare(
      `INSERT INTO cloud_stamp_asset_versions
         (workspace_id, id, asset_id, object_key, mime_type, byte_size,
           original_width_px, original_height_px, aspect_ratio, crop_json, crop_enabled,
           default_width_mm, default_height_mm, schema_version, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)`,
    ).bind(workspaceId, versionId, assetId, objectKey, upload.contentType, upload.bytes.byteLength, upload.originalWidthPx, upload.originalHeightPx, upload.aspectRatio, upload.cropJson, upload.cropEnabled ? 1 : 0, upload.defaultWidthMm, upload.defaultHeightMm, upload.schemaVersion, now),
  ]);
  return { id: assetId, versionId, name: upload.name, cloudName: upload.name, mimeType: upload.contentType, originalWidthPx: upload.originalWidthPx, originalHeightPx: upload.originalHeightPx, aspectRatio: upload.aspectRatio, cropEnabled: upload.cropEnabled, crop: parseCropJson(upload.cropJson), defaultWidthMm: upload.defaultWidthMm, defaultHeightMm: upload.defaultHeightMm, schemaVersion: upload.schemaVersion, updatedAt: now, cloudState: "synced" };
};

const createStampAssetVersion = async (env, workspaceId, assetId, upload) => {
  await getStampVersion(env, workspaceId, assetId);
  const versionId = `stampv_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  const objectKey = stampObjectKey(workspaceId, assetId, versionId, upload.contentType);
  const now = new Date().toISOString();
  const bucket = requireStampBucket(env);
  await bucket.put(objectKey, upload.bytes, {
    httpMetadata: { contentType: upload.contentType, cacheControl: "private, no-store" },
    customMetadata: { workspaceId, assetId, versionId },
  });
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cloud_stamp_asset_versions
         (workspace_id, id, asset_id, object_key, mime_type, byte_size,
           original_width_px, original_height_px, aspect_ratio, crop_json, crop_enabled,
           default_width_mm, default_height_mm, schema_version, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)`,
    ).bind(workspaceId, versionId, assetId, objectKey, upload.contentType, upload.bytes.byteLength, upload.originalWidthPx, upload.originalHeightPx, upload.aspectRatio, upload.cropJson, upload.cropEnabled ? 1 : 0, upload.defaultWidthMm, upload.defaultHeightMm, upload.schemaVersion, now),
    env.DB.prepare(
      `UPDATE cloud_stamp_assets
       SET name = ?3, current_version_id = ?4, updated_at = ?5, deleted_at = NULL
       WHERE workspace_id = ?1 AND id = ?2`,
    ).bind(workspaceId, assetId, upload.name, versionId, now),
  ]);
  return { id: assetId, versionId, name: upload.name, cloudName: upload.name, mimeType: upload.contentType, originalWidthPx: upload.originalWidthPx, originalHeightPx: upload.originalHeightPx, aspectRatio: upload.aspectRatio, cropEnabled: upload.cropEnabled, crop: parseCropJson(upload.cropJson), defaultWidthMm: upload.defaultWidthMm, defaultHeightMm: upload.defaultHeightMm, schemaVersion: upload.schemaVersion, updatedAt: now, cloudState: "synced" };
};

const stampObjectKey = (workspaceId, assetId, versionId, mimeType) => {
  const extension = ({
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
  })[mimeType] || "bin";
  const safeWorkspace = encodeURIComponent(workspaceId).replaceAll("%", "_");
  return `workspaces/${safeWorkspace}/stamps/${assetId}/${versionId}.${extension}`;
};

const VERSION_RETENTION_DAYS = 365;
const VERSION_MINIMUM_COUNT = 30;

const pruneWorkspaceVersions = async (env, workspaceId) => {
  const cutoff = new Date(
    Date.now() - VERSION_RETENTION_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString();
  const expiredVersionQuery = `
    SELECT id
    FROM cloud_workspace_versions
    WHERE workspace_id = ?1
      AND created_at < ?2
      AND id NOT IN (
        SELECT id
        FROM cloud_workspace_versions
        WHERE workspace_id = ?1
        ORDER BY created_at DESC
        LIMIT ${VERSION_MINIMUM_COUNT}
      )`;
  await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM cloud_workspace_version_records
       WHERE version_id IN (${expiredVersionQuery})`,
    ).bind(workspaceId, cutoff),
    env.DB.prepare(
      `DELETE FROM cloud_workspace_versions
       WHERE id IN (${expiredVersionQuery})`,
    ).bind(workspaceId, cutoff),
  ]);
};

const createWorkspaceVersion = async (env, workspaceId, source) => {
  const versionId = `ver_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const safeSource = String(source || "before-change").slice(0, 80);
  const stats = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM cloud_projects WHERE workspace_id = ?1) project_count,
       (SELECT COUNT(*) FROM cloud_contract_templates WHERE workspace_id = ?1) template_count,
       (SELECT COUNT(*) FROM cloud_clause_categories WHERE workspace_id = ?1) category_count,
       (SELECT COUNT(*) FROM cloud_clauses WHERE workspace_id = ?1) clause_count,
       (SELECT COUNT(*) FROM cloud_stamp_assets WHERE workspace_id = ?1 AND deleted_at IS NULL) stamp_asset_count,
       COALESCE((SELECT SUM(LENGTH(id) + LENGTH(name) + LENGTH(data_json)) FROM cloud_projects WHERE workspace_id = ?1), 0)
       + COALESCE((SELECT SUM(LENGTH(id) + LENGTH(name) + LENGTH(notes_json)) FROM cloud_contract_templates WHERE workspace_id = ?1), 0)
       + COALESCE((SELECT SUM(LENGTH(id) + LENGTH(name)) FROM cloud_clause_categories WHERE workspace_id = ?1), 0)
       + COALESCE((SELECT SUM(LENGTH(id) + LENGTH(category) + LENGTH(clause_text)) FROM cloud_clauses WHERE workspace_id = ?1), 0)
       + COALESCE((SELECT SUM(LENGTH(id) + LENGTH(name) + LENGTH(COALESCE(current_version_id, ''))) FROM cloud_stamp_assets WHERE workspace_id = ?1), 0)
       AS byte_size`,
  ).bind(workspaceId).first();

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cloud_workspace_versions
         (id, workspace_id, source, project_count, template_count,
          category_count, clause_count, stamp_asset_count, byte_size, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
    ).bind(
      versionId,
      workspaceId,
      safeSource,
      Number(stats?.project_count || 0),
      Number(stats?.template_count || 0),
      Number(stats?.category_count || 0),
      Number(stats?.clause_count || 0),
      Number(stats?.stamp_asset_count || 0),
      Number(stats?.byte_size || 0),
      createdAt,
    ),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_version_records
         (version_id, entity_type, entity_id, payload_json)
       SELECT ?1, 'project', id,
         json_object('id', id, 'name', name, 'data', json(data_json),
                     'updatedAt', updated_at)
       FROM cloud_projects WHERE workspace_id = ?2`,
    ).bind(versionId, workspaceId),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_version_records
         (version_id, entity_type, entity_id, payload_json)
       SELECT ?1, 'template', id,
         json_object('id', id, 'name', name, 'notes', json(notes_json),
                     'updatedAt', updated_at)
       FROM cloud_contract_templates WHERE workspace_id = ?2`,
    ).bind(versionId, workspaceId),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_version_records
         (version_id, entity_type, entity_id, payload_json)
       SELECT ?1, 'category', id,
         json_object('id', id, 'name', name, 'sortOrder', sort_order,
                     'updatedAt', updated_at)
       FROM cloud_clause_categories WHERE workspace_id = ?2`,
    ).bind(versionId, workspaceId),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_version_records
         (version_id, entity_type, entity_id, payload_json)
       SELECT ?1, 'clause', id,
         json_object('id', id, 'categoryId', COALESCE(category_id, ''),
                     'category', category, 'text', clause_text,
                     'severity', severity, 'sortOrder', sort_order,
                     'isCore', is_core, 'coreOrder', core_order,
                     'updatedAt', updated_at)
       FROM cloud_clauses WHERE workspace_id = ?2`,
    ).bind(versionId, workspaceId),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_version_records
         (version_id, entity_type, entity_id, payload_json)
       SELECT ?1, 'workspaceState', workspace_id,
         json_object('clauseLibraryInitialized', clause_library_initialized,
                     'clauseCategoriesInitialized', clause_categories_initialized,
                     'updatedAt', updated_at)
       FROM cloud_workspace_state WHERE workspace_id = ?2`,
    ).bind(versionId, workspaceId),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_version_records
         (version_id, entity_type, entity_id, payload_json)
       SELECT ?1, 'stampAsset', a.id,
         json_object(
           'id', a.id,
           'name', a.name,
           'currentVersionId', COALESCE(a.current_version_id, ''),
           'updatedAt', a.updated_at,
           'deletedAt', a.deleted_at,
           'version', CASE WHEN v.id IS NULL THEN NULL ELSE json_object(
             'id', v.id,
             'objectKey', v.object_key,
             'mimeType', v.mime_type,
             'byteSize', v.byte_size,
             'originalWidthPx', v.original_width_px,
             'originalHeightPx', v.original_height_px,
             'aspectRatio', v.aspect_ratio,
             'cropEnabled', v.crop_enabled,
             'crop', json(v.crop_json),
             'defaultWidthMm', v.default_width_mm,
             'defaultHeightMm', v.default_height_mm,
             'schemaVersion', v.schema_version,
             'createdAt', v.created_at
           ) END
         )
       FROM cloud_stamp_assets a
       LEFT JOIN cloud_stamp_asset_versions v
         ON v.workspace_id = a.workspace_id AND v.id = a.current_version_id
       WHERE a.workspace_id = ?2`,
    ).bind(versionId, workspaceId),
  ]);
  await pruneWorkspaceVersions(env, workspaceId);
  return versionId;
};

const getWorkspaceVersion = async (env, workspaceId, versionId) => {
  const version = await env.DB.prepare(
    `SELECT id, source, project_count, template_count, category_count,
            clause_count, stamp_asset_count, byte_size, created_at
     FROM cloud_workspace_versions
     WHERE workspace_id = ?1 AND id = ?2
     LIMIT 1`,
  ).bind(workspaceId, versionId).first();
  if (!version) throw new ApiError("找不到版本紀錄", 404);
  const records = await env.DB.prepare(
    `SELECT entity_type, payload_json
     FROM cloud_workspace_version_records
     WHERE version_id = ?1
     ORDER BY entity_type, entity_id`,
  ).bind(versionId).all();
  const snapshot = {
    projects: [],
    templates: [],
    categories: [],
    clauses: [],
    stampAssets: [],
    workspaceState: null,
  };
  for (const record of records.results) {
    const payload = JSON.parse(record.payload_json);
    if (record.entity_type === "project") snapshot.projects.push(payload);
    if (record.entity_type === "template") snapshot.templates.push(payload);
    if (record.entity_type === "category") snapshot.categories.push(payload);
    if (record.entity_type === "clause") snapshot.clauses.push(payload);
    if (record.entity_type === "stampAsset") snapshot.stampAssets.push(payload);
    if (record.entity_type === "workspaceState") snapshot.workspaceState = payload;
  }
  return {
    id: version.id,
    source: version.source,
    projectCount: Number(version.project_count),
    templateCount: Number(version.template_count),
    categoryCount: Number(version.category_count),
    clauseCount: Number(version.clause_count),
    stampAssetCount: Number(version.stamp_asset_count || 0),
    byteSize: Number(version.byte_size),
    createdAt: version.created_at,
    snapshot,
  };
};

const restoreWorkspaceVersion = async (env, workspaceId, versionId) => {
  await getWorkspaceVersion(env, workspaceId, versionId);
  await createWorkspaceVersion(env, workspaceId, "before-restore");
  // The new snapshot may trigger retention cleanup. Re-check before deleting
  // current data so a just-pruned, very old target can never restore as empty.
  await getWorkspaceVersion(env, workspaceId, versionId);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM cloud_clauses WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare("DELETE FROM cloud_clause_categories WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare("DELETE FROM cloud_projects WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare("DELETE FROM cloud_contract_templates WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare("DELETE FROM cloud_workspace_state WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare("DELETE FROM cloud_stamp_asset_versions WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare("DELETE FROM cloud_stamp_assets WHERE workspace_id = ?1").bind(workspaceId),
    env.DB.prepare(
      `INSERT INTO cloud_projects (workspace_id, id, name, data_json, updated_at)
       SELECT ?1,
              json_extract(payload_json, '$.id'),
              json_extract(payload_json, '$.name'),
              json_extract(payload_json, '$.data'),
              json_extract(payload_json, '$.updatedAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2 AND entity_type = 'project'`,
    ).bind(workspaceId, versionId),
    env.DB.prepare(
      `INSERT INTO cloud_contract_templates
         (workspace_id, id, name, notes_json, updated_at)
       SELECT ?1,
              json_extract(payload_json, '$.id'),
              json_extract(payload_json, '$.name'),
              json_extract(payload_json, '$.notes'),
              json_extract(payload_json, '$.updatedAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2 AND entity_type = 'template'`,
    ).bind(workspaceId, versionId),
    env.DB.prepare(
      `INSERT INTO cloud_clause_categories
         (workspace_id, id, name, sort_order, updated_at)
       SELECT ?1,
              json_extract(payload_json, '$.id'),
              json_extract(payload_json, '$.name'),
              json_extract(payload_json, '$.sortOrder'),
              json_extract(payload_json, '$.updatedAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2 AND entity_type = 'category'`,
    ).bind(workspaceId, versionId),
    env.DB.prepare(
      `INSERT INTO cloud_clauses
         (workspace_id, id, category_id, category, clause_text, severity,
          sort_order, is_core, core_order, updated_at)
       SELECT ?1,
              json_extract(payload_json, '$.id'),
              json_extract(payload_json, '$.categoryId'),
              json_extract(payload_json, '$.category'),
              json_extract(payload_json, '$.text'),
              json_extract(payload_json, '$.severity'),
              json_extract(payload_json, '$.sortOrder'),
              json_extract(payload_json, '$.isCore'),
              json_extract(payload_json, '$.coreOrder'),
              json_extract(payload_json, '$.updatedAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2 AND entity_type = 'clause'`,
    ).bind(workspaceId, versionId),
    env.DB.prepare(
      `INSERT INTO cloud_workspace_state
         (workspace_id, clause_library_initialized,
          clause_categories_initialized, updated_at)
       SELECT ?1,
              json_extract(payload_json, '$.clauseLibraryInitialized'),
              json_extract(payload_json, '$.clauseCategoriesInitialized'),
              json_extract(payload_json, '$.updatedAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2 AND entity_type = 'workspaceState'`,
    ).bind(workspaceId, versionId),
    env.DB.prepare(
      `INSERT INTO cloud_stamp_assets
         (workspace_id, id, name, current_version_id, updated_at, created_at, deleted_at)
       SELECT ?1,
              json_extract(payload_json, '$.id'),
              json_extract(payload_json, '$.name'),
              NULLIF(json_extract(payload_json, '$.currentVersionId'), ''),
              json_extract(payload_json, '$.updatedAt'),
              json_extract(payload_json, '$.updatedAt'),
              json_extract(payload_json, '$.deletedAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2 AND entity_type = 'stampAsset'`,
    ).bind(workspaceId, versionId),
    env.DB.prepare(
      `INSERT INTO cloud_stamp_asset_versions
         (workspace_id, id, asset_id, object_key, mime_type, byte_size,
          original_width_px, original_height_px, aspect_ratio, crop_json,
          crop_enabled, default_width_mm, default_height_mm, schema_version, created_at)
       SELECT ?1,
              json_extract(payload_json, '$.version.id'),
              json_extract(payload_json, '$.id'),
              json_extract(payload_json, '$.version.objectKey'),
              json_extract(payload_json, '$.version.mimeType'),
              json_extract(payload_json, '$.version.byteSize'),
              json_extract(payload_json, '$.version.originalWidthPx'),
              json_extract(payload_json, '$.version.originalHeightPx'),
               json_extract(payload_json, '$.version.aspectRatio'),
               json_extract(payload_json, '$.version.crop'),
               COALESCE(json_extract(payload_json, '$.version.cropEnabled'), 0),
               COALESCE(json_extract(payload_json, '$.version.defaultWidthMm'), 18),
               COALESCE(json_extract(payload_json, '$.version.defaultHeightMm'), 18),
               COALESCE(json_extract(payload_json, '$.version.schemaVersion'), 1),
               json_extract(payload_json, '$.version.createdAt')
       FROM cloud_workspace_version_records
       WHERE version_id = ?2
         AND entity_type = 'stampAsset'
         AND json_extract(payload_json, '$.version.id') IS NOT NULL`,
    ).bind(workspaceId, versionId),
  ]);
  await pruneWorkspaceVersions(env, workspaceId);
};

const upsertProject = (env, workspaceId, project) => {
  if (!validId(project?.id) || !validName(project?.name) || !project?.data) {
    throw new ApiError("專案資料格式不正確");
  }
  const updatedAt = normalizeUpdatedAt(project.updatedAt);
  return env.DB.prepare(
    `INSERT INTO cloud_projects (workspace_id, id, name, data_json, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(workspace_id, id) DO UPDATE SET
       name = excluded.name,
       data_json = excluded.data_json,
       updated_at = excluded.updated_at
     WHERE excluded.updated_at >= cloud_projects.updated_at`,
  ).bind(
    workspaceId,
    project.id,
    project.name.trim(),
    JSON.stringify(project.data),
    updatedAt,
  );
};

const upsertTemplate = (env, workspaceId, template) => {
  if (
    !validId(template?.id) ||
    !validName(template?.name) ||
    !Array.isArray(template?.notes)
  ) {
    throw new ApiError("條款範本格式不正確");
  }
  const updatedAt = normalizeUpdatedAt(template.updatedAt);
  return env.DB.prepare(
    `INSERT INTO cloud_contract_templates
       (workspace_id, id, name, notes_json, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(workspace_id, id) DO UPDATE SET
       name = excluded.name,
       notes_json = excluded.notes_json,
       updated_at = excluded.updated_at
     WHERE excluded.updated_at >= cloud_contract_templates.updated_at`,
  ).bind(
    workspaceId,
    template.id,
    template.name.trim(),
    JSON.stringify(template.notes),
    updatedAt,
  );
};

const upsertCategory = (env, workspaceId, category) => {
  const sortOrder = Number(category?.sortOrder);
  if (
    !validId(category?.id) ||
    !validName(category?.name) ||
    !Number.isFinite(sortOrder)
  ) {
    throw new ApiError("條款分類格式不正確");
  }
  const updatedAt = normalizeUpdatedAt(category.updatedAt);
  return env.DB.prepare(
    `INSERT INTO cloud_clause_categories
       (workspace_id, id, name, sort_order, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(workspace_id, id) DO UPDATE SET
       name = excluded.name,
       sort_order = excluded.sort_order,
       updated_at = excluded.updated_at
     WHERE excluded.updated_at >= cloud_clause_categories.updated_at`,
  ).bind(
    workspaceId,
    category.id,
    category.name.trim(),
    Math.trunc(sortOrder),
    updatedAt,
  );
};

const upsertClause = (env, workspaceId, clause) => {
  const categoryId =
    typeof clause?.categoryId === "string" ? clause.categoryId.trim() : "";
  const category = typeof clause?.category === "string" ? clause.category.trim() : "";
  const text = typeof clause?.text === "string" ? clause.text.trim() : "";
  const severity = Number(clause?.severity);
  const sortOrder = Number(clause?.sortOrder);
  const coreOrder = clause?.coreOrder == null ? null : Number(clause.coreOrder);
  if (
    !validId(clause?.id) ||
    (categoryId && !validId(categoryId)) ||
    !category ||
    category.length > 120 ||
    !text ||
    text.length > 5000 ||
    !Number.isInteger(severity) ||
    severity < 1 ||
    severity > 3 ||
    !Number.isFinite(sortOrder) ||
    (coreOrder != null && (!Number.isInteger(coreOrder) || coreOrder < 1))
  ) {
    throw new ApiError("條款格式不正確");
  }
  const updatedAt = normalizeUpdatedAt(clause.updatedAt);
  return env.DB.prepare(
    `INSERT INTO cloud_clauses
       (workspace_id, id, category_id, category, clause_text, severity,
        sort_order, is_core, core_order, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
     ON CONFLICT(workspace_id, id) DO UPDATE SET
       category_id = excluded.category_id,
       category = excluded.category,
       clause_text = excluded.clause_text,
       severity = excluded.severity,
       sort_order = excluded.sort_order,
       is_core = excluded.is_core,
       core_order = excluded.core_order,
       updated_at = excluded.updated_at
     WHERE excluded.updated_at >= cloud_clauses.updated_at`,
  ).bind(
    workspaceId,
    clause.id,
    categoryId || null,
    category,
    text,
    severity,
    Math.trunc(sortOrder),
    clause.isCore ? 1 : 0,
    coreOrder,
    updatedAt,
  );
};

const googleLogin = async (request, env) => {
  if (!env.GOOGLE_CLIENT_ID) {
    throw new ApiError("Google 登入尚未完成 OAuth Client ID 設定", 503);
  }
  const body = await readJson(request);
  if (typeof body.credential !== "string" || body.credential.length > 10000) {
    throw new ApiError("缺少 Google 登入憑證", 401);
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(body.credential, GOOGLE_JWKS, {
      audience: env.GOOGLE_CLIENT_ID,
      issuer: ["accounts.google.com", "https://accounts.google.com"],
    }));
  } catch {
    throw new ApiError("Google 登入憑證驗證失敗", 401);
  }

  if (
    !payload.sub ||
    !payload.email ||
    ![true, "true"].includes(payload.email_verified)
  ) {
    throw new ApiError("Google 帳號缺少已驗證的電子郵件", 401);
  }

  const now = new Date();
  const existing = await env.DB.prepare(
    "SELECT id FROM cloud_users WHERE google_sub = ?1 LIMIT 1",
  ).bind(String(payload.sub)).first();
  const userId =
    existing?.id ||
    `usr_${(await sha256(`google:${String(payload.sub)}`)).slice(0, 32)}`;
  const sessionToken = randomToken();
  const tokenHash = await sha256(sessionToken);
  const expiresAt = new Date(
    now.getTime() + SESSION_LIFETIME_SECONDS * 1000,
  ).toISOString();
  const nowIso = now.toISOString();
  const user = {
    id: userId,
    email: String(payload.email),
    name: String(payload.name || payload.email),
    picture: typeof payload.picture === "string" ? payload.picture : "",
  };

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO cloud_users
         (id, google_sub, email, display_name, picture_url, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
       ON CONFLICT(google_sub) DO UPDATE SET
         email = excluded.email,
         display_name = excluded.display_name,
         picture_url = excluded.picture_url,
         updated_at = excluded.updated_at`,
    ).bind(
      user.id,
      String(payload.sub),
      user.email,
      user.name,
      user.picture,
      nowIso,
    ),
    env.DB.prepare(
      "DELETE FROM cloud_sessions WHERE expires_at <= ?1",
    ).bind(nowIso),
    env.DB.prepare(
      `INSERT INTO cloud_sessions
         (token_hash, user_id, expires_at, created_at)
       VALUES (?1, ?2, ?3, ?4)`,
    ).bind(tokenHash, user.id, expiresAt, nowIso),
  ]);

  return json({ token: sessionToken, expiresAt, user });
};

const routeRequest = async (request, env) => {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);

  if (request.method === "GET" && url.pathname === "/health") {
    return json({ ok: true, service: "kino-quotation-data-api" });
  }
  if (request.method === "GET" && url.pathname === "/api/config") {
    return json({
      googleClientId: env.GOOGLE_CLIENT_ID || "",
      googleLoginEnabled: Boolean(env.GOOGLE_CLIENT_ID),
      microsoftClientId: env.MICROSOFT_CLIENT_ID || "",
      oneDriveLoginEnabled: Boolean(env.MICROSOFT_CLIENT_ID),
    });
  }
  if (request.method === "POST" && url.pathname === "/api/auth/google") {
    return googleLogin(request, env);
  }

  const auth = await getAuthContext(request, env);
  if (!auth) {
    throw new ApiError("請先使用 Google 登入或輸入同步金鑰", 401);
  }

  if (request.method === "GET" && url.pathname === "/api/auth/me") {
    return json({
      authType: auth.type,
      user: auth.user,
      expiresAt: auth.expiresAt,
    });
  }
  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    if (auth.type === "google") {
      await env.DB.prepare(
        "DELETE FROM cloud_sessions WHERE token_hash = ?1",
      ).bind(auth.tokenHash).run();
    }
    return json({ ok: true });
  }

  const workspaceId = auth.workspaceId;

  if (request.method === "GET" && url.pathname === "/api/versions") {
    const versions = await env.DB.prepare(
       `SELECT id, source, project_count, template_count, category_count,
              clause_count, stamp_asset_count, byte_size, created_at
       FROM cloud_workspace_versions
       WHERE workspace_id = ?1
       ORDER BY created_at DESC
       LIMIT 200`,
    ).bind(workspaceId).all();
    return json({
      versions: versions.results.map((version) => ({
        id: version.id,
        source: version.source,
        projectCount: Number(version.project_count),
        templateCount: Number(version.template_count),
        categoryCount: Number(version.category_count),
        clauseCount: Number(version.clause_count),
        stampAssetCount: Number(version.stamp_asset_count || 0),
        byteSize: Number(version.byte_size),
        createdAt: version.created_at,
      })),
      retentionDays: VERSION_RETENTION_DAYS,
      minimumVersions: VERSION_MINIMUM_COUNT,
    });
  }

  if (request.method === "GET" && url.pathname === "/api/stamps") {
    const assets = await getStampRows(env, workspaceId).all();
    return json({ assets: assets.results.map(mapStampAsset) });
  }

  if (request.method === "POST" && url.pathname === "/api/stamps") {
    const upload = await readStampFormUpload(request);
    await createWorkspaceVersion(env, workspaceId, "before-stamp-create");
    const asset = await createStampAsset(env, workspaceId, upload);
    return json({ asset }, 201);
  }

  if (parts[0] === "api" && parts[1] === "stamps" && parts[2]) {
    const assetId = decodeURIComponent(parts[2]);
    if (!validStampId(assetId)) throw new ApiError("印章資產 ID 不正確");
    if (request.method === "GET" && parts[3] === "content") {
      const versionId = String(url.searchParams.get("version") || "");
      const version = await getStampVersion(env, workspaceId, assetId, versionId);
      const object = await requireStampBucket(env).get(version.object_key);
      if (!object) throw new ApiError("找不到印章檔案", 404);
      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("etag", object.httpEtag);
      headers.set("cache-control", "private, no-store");
      headers.set("content-disposition", "inline");
      return new Response(object.body, { status: 200, headers });
    }
    if (request.method === "PUT" && parts[3] === "content") {
      const upload = await readStampFormUpload(request);
      await createWorkspaceVersion(env, workspaceId, "before-stamp-version");
      const asset = await createStampAssetVersion(env, workspaceId, assetId, upload);
      return json({ asset });
    }
    if (request.method === "PUT" && !parts[3]) {
      const body = await readJson(request);
      if (!validStampName(body.name)) throw new ApiError("印章名稱格式不正確");
      await createWorkspaceVersion(env, workspaceId, "before-stamp-rename");
      const result = await env.DB.prepare(
        `UPDATE cloud_stamp_assets
         SET name = ?3, updated_at = ?4
         WHERE workspace_id = ?1 AND id = ?2 AND deleted_at IS NULL`,
      ).bind(workspaceId, assetId, body.name.trim(), new Date().toISOString()).run();
      if (!result.meta.changes) throw new ApiError("找不到印章資產", 404);
      return json({ ok: true });
    }
    if (request.method === "DELETE" && !parts[3]) {
      await createWorkspaceVersion(env, workspaceId, "before-stamp-delete");
      const result = await env.DB.prepare(
        `UPDATE cloud_stamp_assets
         SET deleted_at = ?3, updated_at = ?3
         WHERE workspace_id = ?1 AND id = ?2 AND deleted_at IS NULL`,
      ).bind(workspaceId, assetId, new Date().toISOString()).run();
      if (!result.meta.changes) throw new ApiError("找不到印章資產", 404);
      return json({ ok: true });
    }
  }

  if (parts[0] === "api" && parts[1] === "versions" && parts[2]) {
    const versionId = decodeURIComponent(parts[2]);
    if (!validId(versionId)) throw new ApiError("版本 ID 不正確");
    if (request.method === "GET") {
      return json(await getWorkspaceVersion(env, workspaceId, versionId));
    }
    if (request.method === "POST" && parts[3] === "restore") {
      await restoreWorkspaceVersion(env, workspaceId, versionId);
      return json({ ok: true, restoredVersionId: versionId });
    }
  }

  if (request.method === "GET" && url.pathname === "/api/sync") {
    const [projects, templates, categories, clauses, workspaceState] =
      await Promise.all([
        env.DB.prepare(
          `SELECT id, name, data_json, updated_at
           FROM cloud_projects
           WHERE workspace_id = ?1
           ORDER BY updated_at DESC`,
        ).bind(workspaceId).all(),
        env.DB.prepare(
          `SELECT id, name, notes_json, updated_at
           FROM cloud_contract_templates
           WHERE workspace_id = ?1
           ORDER BY updated_at DESC`,
        ).bind(workspaceId).all(),
        env.DB.prepare(
          `SELECT id, name, sort_order, updated_at
           FROM cloud_clause_categories
           WHERE workspace_id = ?1
           ORDER BY sort_order, name`,
        ).bind(workspaceId).all(),
        env.DB.prepare(
          `SELECT id, category_id, category, clause_text, severity, sort_order,
                  is_core, core_order, updated_at
           FROM cloud_clauses
           WHERE workspace_id = ?1
           ORDER BY CASE WHEN is_core = 1 THEN 0 ELSE 1 END,
                    core_order, category, severity, sort_order`,
        ).bind(workspaceId).all(),
        env.DB.prepare(
          `SELECT clause_library_initialized, clause_categories_initialized
           FROM cloud_workspace_state
           WHERE workspace_id = ?1
           LIMIT 1`,
        ).bind(workspaceId).first(),
      ]);
    return json({
      authType: auth.type,
      user: auth.user,
      projects: projects.results.map(mapProject),
      templates: templates.results.map(mapTemplate),
      categories: categories.results.map(mapCategory),
      clauses: clauses.results.map(mapClause),
      clauseLibraryInitialized: Boolean(
        workspaceState?.clause_library_initialized,
      ),
      clauseCategoriesInitialized: Boolean(
        workspaceState?.clause_categories_initialized,
      ),
      serverTime: new Date().toISOString(),
    });
  }

  if (request.method === "POST" && url.pathname === "/api/sync") {
    const body = await readJson(request);
    const projects = Array.isArray(body.projects) ? body.projects : [];
    const templates = Array.isArray(body.templates) ? body.templates : [];
    const categories = Array.isArray(body.categories) ? body.categories : [];
    const clauses = Array.isArray(body.clauses) ? body.clauses : [];
    const deletedProjectIds = Array.isArray(body.deletedProjectIds)
      ? body.deletedProjectIds.filter(validId)
      : [];
    const deletedTemplateIds = Array.isArray(body.deletedTemplateIds)
      ? body.deletedTemplateIds.filter(validId)
      : [];
    const deletedCategoryIds = Array.isArray(body.deletedCategoryIds)
      ? body.deletedCategoryIds.filter(validId)
      : [];
    const deletedClauseIds = Array.isArray(body.deletedClauseIds)
      ? body.deletedClauseIds.filter(validId)
      : [];

    if (
      projects.length > 200 ||
      templates.length > 200 ||
      categories.length > 200 ||
      clauses.length > 500 ||
      deletedProjectIds.length > 200 ||
      deletedTemplateIds.length > 200 ||
      deletedCategoryIds.length > 200 ||
      deletedClauseIds.length > 500
    ) {
      throw new ApiError("同步項目數量超過上限");
    }

    const statements = [
      ...deletedProjectIds.map((id) =>
        env.DB.prepare(
          "DELETE FROM cloud_projects WHERE workspace_id = ?1 AND id = ?2",
        ).bind(workspaceId, id),
      ),
      ...deletedTemplateIds.map((id) =>
        env.DB.prepare(
          `DELETE FROM cloud_contract_templates
           WHERE workspace_id = ?1 AND id = ?2`,
        ).bind(workspaceId, id),
      ),
      ...deletedCategoryIds.flatMap((id) => [
        env.DB.prepare(
          "DELETE FROM cloud_clauses WHERE workspace_id = ?1 AND category_id = ?2",
        ).bind(workspaceId, id),
        env.DB.prepare(
          `DELETE FROM cloud_clause_categories
           WHERE workspace_id = ?1 AND id = ?2`,
        ).bind(workspaceId, id),
      ]),
      ...deletedClauseIds.map((id) =>
        env.DB.prepare(
          "DELETE FROM cloud_clauses WHERE workspace_id = ?1 AND id = ?2",
        ).bind(workspaceId, id),
      ),
      ...projects.map((project) => upsertProject(env, workspaceId, project)),
      ...templates.map((template) => upsertTemplate(env, workspaceId, template)),
      ...categories.map((category) =>
        upsertCategory(env, workspaceId, category),
      ),
      ...clauses.map((clause) => upsertClause(env, workspaceId, clause)),
    ];

    if (body.initializeClauseLibrary || body.initializeClauseCategories) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO cloud_workspace_state
             (workspace_id, clause_library_initialized,
              clause_categories_initialized, updated_at)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(workspace_id) DO UPDATE SET
             clause_library_initialized =
               MAX(cloud_workspace_state.clause_library_initialized,
                   excluded.clause_library_initialized),
             clause_categories_initialized =
               MAX(cloud_workspace_state.clause_categories_initialized,
                   excluded.clause_categories_initialized),
             updated_at = excluded.updated_at`,
        ).bind(
          workspaceId,
          body.initializeClauseLibrary ? 1 : 0,
          body.initializeClauseCategories ? 1 : 0,
          new Date().toISOString(),
        ),
      );
    }
    if (statements.length) {
      await createWorkspaceVersion(env, workspaceId, "before-sync");
      await env.DB.batch(statements);
    }
    return json({
      ok: true,
      projects: projects.length,
      templates: templates.length,
      categories: categories.length,
      clauses: clauses.length,
      deletedProjects: deletedProjectIds.length,
      deletedTemplates: deletedTemplateIds.length,
      deletedCategories: deletedCategoryIds.length,
      deletedClauses: deletedClauseIds.length,
    });
  }

  if (parts[0] === "api" && parts[1] === "projects" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) throw new ApiError("專案 ID 不正確");
    if (request.method === "PUT") {
      const body = await readJson(request);
      await createWorkspaceVersion(env, workspaceId, "before-project-update");
      await upsertProject(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await createWorkspaceVersion(env, workspaceId, "before-project-delete");
      await env.DB.prepare(
        "DELETE FROM cloud_projects WHERE workspace_id = ?1 AND id = ?2",
      ).bind(workspaceId, id).run();
      return json({ ok: true });
    }
  }

  if (parts[0] === "api" && parts[1] === "templates" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) throw new ApiError("範本 ID 不正確");
    if (request.method === "PUT") {
      const body = await readJson(request);
      await createWorkspaceVersion(env, workspaceId, "before-template-update");
      await upsertTemplate(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await createWorkspaceVersion(env, workspaceId, "before-template-delete");
      await env.DB.prepare(
        `DELETE FROM cloud_contract_templates
         WHERE workspace_id = ?1 AND id = ?2`,
      ).bind(workspaceId, id).run();
      return json({ ok: true });
    }
  }

  if (parts[0] === "api" && parts[1] === "categories" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) throw new ApiError("分類 ID 不正確");
    if (request.method === "PUT") {
      const body = await readJson(request);
      const category = { ...body, id };
      const name = String(category.name || "").trim();
      await createWorkspaceVersion(env, workspaceId, "before-category-update");
      await env.DB.batch([
        upsertCategory(env, workspaceId, category),
        env.DB.prepare(
          `UPDATE cloud_clauses
           SET category = ?3, updated_at = ?4
           WHERE workspace_id = ?1 AND category_id = ?2`,
        ).bind(
          workspaceId,
          id,
          name,
          normalizeUpdatedAt(category.updatedAt),
        ),
      ]);
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await createWorkspaceVersion(env, workspaceId, "before-category-delete");
      await env.DB.batch([
        env.DB.prepare(
          "DELETE FROM cloud_clauses WHERE workspace_id = ?1 AND category_id = ?2",
        ).bind(workspaceId, id),
        env.DB.prepare(
          `DELETE FROM cloud_clause_categories
           WHERE workspace_id = ?1 AND id = ?2`,
        ).bind(workspaceId, id),
      ]);
      return json({ ok: true });
    }
  }

  if (parts[0] === "api" && parts[1] === "clauses" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) throw new ApiError("條款 ID 不正確");
    if (request.method === "PUT") {
      const body = await readJson(request);
      await createWorkspaceVersion(env, workspaceId, "before-clause-update");
      await upsertClause(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await createWorkspaceVersion(env, workspaceId, "before-clause-delete");
      await env.DB.prepare(
        "DELETE FROM cloud_clauses WHERE workspace_id = ?1 AND id = ?2",
      ).bind(workspaceId, id).run();
      return json({ ok: true });
    }
  }

  throw new ApiError("找不到 API 路徑", 404);
};

export default {
  async fetch(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const origin = request.headers.get("origin");
    if (origin && !corsHeaders["access-control-allow-origin"]) {
      return json({ error: "不允許此網域存取" }, 403);
    }
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      const response = await routeRequest(request, env);
      const securedResponse = new Response(response.body, response);
      Object.entries(corsHeaders).forEach(([key, value]) =>
        securedResponse.headers.set(key, value),
      );
      securedResponse.headers.set("cache-control", "no-store");
      securedResponse.headers.set("x-content-type-options", "nosniff");
      return securedResponse;
    } catch (error) {
      const status =
        error instanceof ApiError ? error.status : 500;
      if (!(error instanceof ApiError)) console.error(error);
      const message =
        error?.message === "PAYLOAD_TOO_LARGE"
          ? "同步資料超過大小上限"
          : error instanceof ApiError
            ? error.message
            : "伺服器處理失敗";
      return json({ error: message }, status, corsHeaders);
    }
  },
};
