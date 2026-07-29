import { createRemoteJWKSet, jwtVerify } from "jose";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const MAX_BODY_BYTES = 2 * 1024 * 1024;
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
    if (statements.length) await env.DB.batch(statements);
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
      await upsertProject(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
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
      await upsertTemplate(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
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
      await upsertClause(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
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
