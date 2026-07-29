const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const MAX_BODY_BYTES = 2 * 1024 * 1024;

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

const hashWorkspaceKey = async (workspaceKey) => {
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(workspaceKey));
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
};

const getWorkspaceId = async (request) => {
  const header = request.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (token.length < 20 || token.length > 200) return "";
  return hashWorkspaceKey(token);
};

const readJson = async (request) => {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_BODY_BYTES) throw new Error("PAYLOAD_TOO_LARGE");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) {
    throw new Error("PAYLOAD_TOO_LARGE");
  }
  return JSON.parse(text || "{}");
};

const validId = (value) =>
  typeof value === "string" && value.length > 0 && value.length <= 160;

const validName = (value) =>
  typeof value === "string" && value.trim().length > 0 && value.trim().length <= 200;

const normalizeUpdatedAt = (value) => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : new Date().toISOString();
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

const mapClause = (row) => ({
  id: row.id,
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
    throw new Error("INVALID_PROJECT");
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
  ).bind(workspaceId, project.id, project.name.trim(), JSON.stringify(project.data), updatedAt);
};

const upsertTemplate = (env, workspaceId, template) => {
  if (!validId(template?.id) || !validName(template?.name) || !Array.isArray(template?.notes)) {
    throw new Error("INVALID_TEMPLATE");
  }
  const updatedAt = normalizeUpdatedAt(template.updatedAt);
  return env.DB.prepare(
    `INSERT INTO cloud_contract_templates (workspace_id, id, name, notes_json, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(workspace_id, id) DO UPDATE SET
       name = excluded.name,
       notes_json = excluded.notes_json,
       updated_at = excluded.updated_at
     WHERE excluded.updated_at >= cloud_contract_templates.updated_at`,
  ).bind(workspaceId, template.id, template.name.trim(), JSON.stringify(template.notes), updatedAt);
};

const upsertClause = (env, workspaceId, clause) => {
  const category = typeof clause?.category === "string" ? clause.category.trim() : "";
  const text = typeof clause?.text === "string" ? clause.text.trim() : "";
  const severity = Number(clause?.severity);
  const sortOrder = Number(clause?.sortOrder);
  const coreOrder = clause?.coreOrder == null ? null : Number(clause.coreOrder);
  if (
    !validId(clause?.id) ||
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
    throw new Error("INVALID_CLAUSE");
  }
  const updatedAt = normalizeUpdatedAt(clause.updatedAt);
  return env.DB.prepare(
    `INSERT INTO cloud_clauses
       (workspace_id, id, category, clause_text, severity, sort_order, is_core, core_order, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
     ON CONFLICT(workspace_id, id) DO UPDATE SET
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
    category,
    text,
    severity,
    Math.trunc(sortOrder),
    clause.isCore ? 1 : 0,
    coreOrder,
    updatedAt,
  );
};

const routeRequest = async (request, env) => {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);

  if (request.method === "GET" && url.pathname === "/health") {
    return json({ ok: true, service: "kino-quotation-data-api" });
  }

  const workspaceId = await getWorkspaceId(request);
  if (!workspaceId) {
    return json({ error: "未授權的雲端同步請求" }, 401);
  }

  if (request.method === "GET" && url.pathname === "/api/sync") {
    const [projects, templates, clauses, workspaceState] = await Promise.all([
      env.DB.prepare("SELECT id, name, data_json, updated_at FROM cloud_projects WHERE workspace_id = ?1 ORDER BY updated_at DESC").bind(workspaceId).all(),
      env.DB.prepare("SELECT id, name, notes_json, updated_at FROM cloud_contract_templates WHERE workspace_id = ?1 ORDER BY updated_at DESC").bind(workspaceId).all(),
      env.DB.prepare(
        `SELECT id, category, clause_text, severity, sort_order, is_core, core_order, updated_at
         FROM cloud_clauses
         WHERE workspace_id = ?1
         ORDER BY CASE WHEN is_core = 1 THEN 0 ELSE 1 END, core_order, category, severity, sort_order`,
      ).bind(workspaceId).all(),
      env.DB.prepare(
        "SELECT clause_library_initialized FROM cloud_workspace_state WHERE workspace_id = ?1",
      ).bind(workspaceId).first(),
    ]);
    return json({
      projects: projects.results.map(mapProject),
      templates: templates.results.map(mapTemplate),
      clauses: clauses.results.map(mapClause),
      clauseLibraryInitialized: Boolean(workspaceState?.clause_library_initialized),
      serverTime: new Date().toISOString(),
    });
  }

  if (request.method === "POST" && url.pathname === "/api/sync") {
    const body = await readJson(request);
    const projects = Array.isArray(body.projects) ? body.projects : [];
    const templates = Array.isArray(body.templates) ? body.templates : [];
    const clauses = Array.isArray(body.clauses) ? body.clauses : [];
    const deletedProjectIds = Array.isArray(body.deletedProjectIds)
      ? body.deletedProjectIds.filter(validId)
      : [];
    const deletedTemplateIds = Array.isArray(body.deletedTemplateIds)
      ? body.deletedTemplateIds.filter(validId)
      : [];
    const deletedClauseIds = Array.isArray(body.deletedClauseIds)
      ? body.deletedClauseIds.filter(validId)
      : [];
    if (
      projects.length > 200 ||
      templates.length > 200 ||
      clauses.length > 500 ||
      deletedProjectIds.length > 200 ||
      deletedTemplateIds.length > 200 ||
      deletedClauseIds.length > 500
    ) {
      return json({ error: "同步項目過多" }, 400);
    }
    const statements = [
      ...deletedProjectIds.map((id) =>
        env.DB.prepare(
          "DELETE FROM cloud_projects WHERE workspace_id = ?1 AND id = ?2",
        ).bind(workspaceId, id),
      ),
      ...deletedTemplateIds.map((id) =>
        env.DB.prepare(
          "DELETE FROM cloud_contract_templates WHERE workspace_id = ?1 AND id = ?2",
        ).bind(workspaceId, id),
      ),
      ...deletedClauseIds.map((id) =>
        env.DB.prepare(
          "DELETE FROM cloud_clauses WHERE workspace_id = ?1 AND id = ?2",
        ).bind(workspaceId, id),
      ),
      ...projects.map((project) => upsertProject(env, workspaceId, project)),
      ...templates.map((template) => upsertTemplate(env, workspaceId, template)),
      ...clauses.map((clause) => upsertClause(env, workspaceId, clause)),
    ];
    if (body.initializeClauseLibrary) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO cloud_workspace_state (workspace_id, clause_library_initialized, updated_at)
           VALUES (?1, 1, ?2)
           ON CONFLICT(workspace_id) DO UPDATE SET
             clause_library_initialized = 1,
             updated_at = excluded.updated_at`,
        ).bind(workspaceId, new Date().toISOString()),
      );
    }
    if (statements.length) await env.DB.batch(statements);
    return json({
      ok: true,
      projects: projects.length,
      templates: templates.length,
      clauses: clauses.length,
      deletedProjects: deletedProjectIds.length,
      deletedTemplates: deletedTemplateIds.length,
      deletedClauses: deletedClauseIds.length,
    });
  }

  if (parts[0] === "api" && parts[1] === "projects" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) return json({ error: "專案 ID 無效" }, 400);
    if (request.method === "PUT") {
      const body = await readJson(request);
      await upsertProject(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM cloud_projects WHERE workspace_id = ?1 AND id = ?2").bind(workspaceId, id).run();
      return json({ ok: true });
    }
  }

  if (parts[0] === "api" && parts[1] === "templates" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) return json({ error: "範本 ID 無效" }, 400);
    if (request.method === "PUT") {
      const body = await readJson(request);
      await upsertTemplate(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM cloud_contract_templates WHERE workspace_id = ?1 AND id = ?2").bind(workspaceId, id).run();
      return json({ ok: true });
    }
  }

  if (parts[0] === "api" && parts[1] === "clauses" && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    if (!validId(id)) return json({ error: "條款 ID 無效" }, 400);
    if (request.method === "PUT") {
      const body = await readJson(request);
      await upsertClause(env, workspaceId, { ...body, id }).run();
      return json({ ok: true });
    }
    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM cloud_clauses WHERE workspace_id = ?1 AND id = ?2").bind(workspaceId, id).run();
      return json({ ok: true });
    }
  }

  return json({ error: "找不到 API 路徑" }, 404);
};

export default {
  async fetch(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const origin = request.headers.get("origin");
    if (origin && !corsHeaders["access-control-allow-origin"]) {
      return json({ error: "不允許的網站來源" }, 403);
    }
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      const response = await routeRequest(request, env);
      const securedResponse = new Response(response.body, response);
      Object.entries(corsHeaders).forEach(([key, value]) => securedResponse.headers.set(key, value));
      securedResponse.headers.set("cache-control", "no-store");
      securedResponse.headers.set("x-content-type-options", "nosniff");
      return securedResponse;
    } catch (error) {
      const status = error?.message === "PAYLOAD_TOO_LARGE" ? 413 : 400;
      return json(
        { error: status === 413 ? "同步資料過大" : "同步資料格式錯誤" },
        status,
        corsHeaders,
      );
    }
  },
};
