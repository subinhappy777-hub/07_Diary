const crypto = require("node:crypto");
const { promisify } = require("node:util");

const scrypt = promisify(crypto.scrypt);
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE = "harugyeol_session";
const INVALID_LOGIN = "아이디 또는 비밀번호가 올바르지 않습니다.";
const EMPTY_SALT = Buffer.alloc(16);

function json(res, status, value) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify(value));
}

function cookie(res, value, clear = false) {
  const age = clear ? 0 : Math.floor(SESSION_MS / 1000);
  res.setHeader("set-cookie", `${COOKIE}=${clear ? "" : value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`);
}

function readCookie(req) {
  const value = String(req.headers.cookie || "");
  for (const part of value.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === COOKIE) return rest.join("=");
  }
  return "";
}

function cleanData(value) {
  const d = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    plans: Array.isArray(d.plans) ? d.plans : [],
    tasks: Array.isArray(d.tasks) ? d.tasks : [],
    runs: Array.isArray(d.runs) ? d.runs : [],
    expenses: Array.isArray(d.expenses) ? d.expenses : [],
    media: Array.isArray(d.media) ? d.media : [],
    weekGoals: Array.isArray(d.weekGoals) ? d.weekGoals : [],
    reflection: typeof d.reflection === "string" ? d.reflection : "",
    monthBudgets: d.monthBudgets && typeof d.monthBudgets === "object" && !Array.isArray(d.monthBudgets) ? d.monthBudgets : {},
    experiment: d.experiment && typeof d.experiment === "object" && !Array.isArray(d.experiment) ? d.experiment : null,
  };
}

function mergeLegacy(oldValue, currentValue) {
  const oldData = cleanData(oldValue);
  const current = cleanData(currentValue);
  for (const key of ["plans", "tasks", "runs", "expenses", "media", "weekGoals"]) {
    const ids = new Set(current[key].map((x) => x?.id).filter(Boolean));
    current[key] = [...current[key], ...oldData[key].filter((x) => !x?.id || !ids.has(x.id))];
  }
  if (!current.reflection) current.reflection = oldData.reflection;
  if (!Object.keys(current.monthBudgets).length) current.monthBudgets = oldData.monthBudgets;
  if (!current.experiment) current.experiment = oldData.experiment;
  return current;
}

function config() {
  const url = String(process.env.SUPABASE_URL || "").replace(/\/$/, "");
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
  if (!url || !key) throw Object.assign(new Error("서버 설정이 필요합니다."), { status: 503 });
  return { url, key };
}

async function dbRequest(resource, { method = "GET", body, prefer = "" } = {}) {
  const { url, key } = config();
  const headers = { apikey: key, accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (prefer) headers.prefer = prefer;
  const response = await fetch(`${url}/rest/v1/${resource}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!response.ok) {
    const error = new Error("저장 서버 요청에 실패했습니다.");
    error.status = response.status;
    error.code = data?.code || "";
    throw error;
  }
  return data;
}

function normalizedUsername(value) {
  return String(value || "").trim().toLocaleLowerCase("en-US");
}

function bodyObject(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body || "{}"); } catch { return null; }
  }
  return {};
}

function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const requestHost = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
    return new URL(origin).host === requestHost;
  } catch { return false; }
}

async function hashPassword(password, salt) {
  return (await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 })).toString("hex");
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function session(req) {
  const token = readCookie(req);
  if (!token) return null;
  const now = new Date().toISOString();
  const hash = tokenHash(token);
  const rows = await dbRequest(`diary_sessions?token_hash=eq.${hash}&expires_at=gt.${encodeURIComponent(now)}&select=user_id&limit=1`);
  const userId = rows?.[0]?.user_id;
  if (!userId) return null;
  const users = await dbRequest(`diary_users?id=eq.${encodeURIComponent(userId)}&select=username&limit=1`);
  return users?.[0] ? { id: userId, username: users[0].username, token } : null;
}

async function newSession(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_MS).toISOString();
  await dbRequest("diary_sessions", {
    method: "POST",
    body: { token_hash: tokenHash(token), user_id: userId, expires_at: expiresAt },
    prefer: "return=minimal",
  });
  return token;
}

async function handle(req, res, endpoint) {
  if (!originAllowed(req)) return json(res, 403, { error: "허용되지 않은 출처입니다." });
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.setHeader("allow", "GET, POST, PUT, OPTIONS");
    return res.end();
  }
  if (req.headers["content-length"] && Number(req.headers["content-length"]) > 2_000_000) {
    return json(res, 413, { error: "요청이 너무 큽니다." });
  }
  const body = bodyObject(req);
  if (!body) return json(res, 400, { error: "요청 형식이 올바르지 않습니다." });

  if (endpoint === "signup" && req.method === "POST") {
    const username = String(body.username || "").trim();
    const usernameNorm = normalizedUsername(username);
    const password = String(body.password || "");
    if (!/^[\p{L}\p{N}_.-]{3,32}$/u.test(username)) return json(res, 400, { error: "아이디는 3~32자의 문자, 숫자, ., _, -로 입력해 주세요." });
    if (password.length < 10 || Buffer.byteLength(password) > 1024) return json(res, 400, { error: "비밀번호는 10자 이상 입력해 주세요." });

    const id = crypto.randomUUID();
    const salt = crypto.randomBytes(16);
    const passwordHash = await hashPassword(password, salt);
    try {
      await dbRequest("rpc/create_diary_account", {
        method: "POST",
        body: {
          p_id: id,
          p_username: username,
          p_username_norm: usernameNorm,
          p_password_hash: passwordHash,
          p_salt: salt.toString("hex"),
          p_created_at: new Date().toISOString(),
          p_data: cleanData(body.legacyData),
        },
      });
    } catch (error) {
      if (error.code === "23505" || error.status === 409) return json(res, 409, { error: "이미 사용 중인 아이디입니다." });
      throw error;
    }
    cookie(res, await newSession(id));
    return json(res, 201, { username });
  }

  if (endpoint === "login" && req.method === "POST") {
    const usernameNorm = normalizedUsername(body.username);
    const password = String(body.password || "");
    const users = await dbRequest(`diary_users?username_norm=eq.${encodeURIComponent(usernameNorm)}&select=id,username,password_hash,salt&limit=1`);
    const user = users?.[0];
    const salt = user ? Buffer.from(user.salt, "hex") : EMPTY_SALT;
    const computed = await hashPassword(password, salt);
    const validHash = user?.password_hash && /^[a-f0-9]{128}$/i.test(user.password_hash);
    const valid = Boolean(validHash && crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(user.password_hash, "hex")));
    if (!valid) return json(res, 401, { error: INVALID_LOGIN });

    if (body.legacyData && typeof body.legacyData === "object") {
      const rows = await dbRequest(`diary_data?user_id=eq.${encodeURIComponent(user.id)}&select=data_json&limit=1`);
      const merged = mergeLegacy(body.legacyData, rows?.[0]?.data_json || {});
      await dbRequest("diary_data?on_conflict=user_id", {
        method: "POST",
        body: { user_id: user.id, data_json: merged, updated_at: new Date().toISOString() },
        prefer: "resolution=merge-duplicates,return=minimal",
      });
    }
    cookie(res, await newSession(user.id));
    return json(res, 200, { username: user.username });
  }

  if (endpoint === "logout" && req.method === "POST") {
    const token = readCookie(req);
    if (token) await dbRequest(`diary_sessions?token_hash=eq.${tokenHash(token)}`, { method: "DELETE", prefer: "return=minimal" });
    cookie(res, "", true);
    return json(res, 200, { ok: true });
  }

  const user = await session(req);
  if (!user) return json(res, 401, { error: "로그인이 필요합니다." });
  if (endpoint === "session" && req.method === "GET") return json(res, 200, { username: user.username });
  if (endpoint === "data" && req.method === "GET") {
    const rows = await dbRequest(`diary_data?user_id=eq.${encodeURIComponent(user.id)}&select=data_json&limit=1`);
    return json(res, 200, { data: cleanData(rows?.[0]?.data_json || {}) });
  }
  if (endpoint === "data" && req.method === "PUT") {
    const data = cleanData(body.data);
    await dbRequest("diary_data?on_conflict=user_id", {
      method: "POST",
      body: { user_id: user.id, data_json: data, updated_at: new Date().toISOString() },
      prefer: "resolution=merge-duplicates,return=minimal",
    });
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: "요청한 자료를 찾을 수 없습니다." });
}

function handler(endpoint) {
  return async (req, res) => {
    try { return await handle(req, res, endpoint); }
    catch (error) {
      const status = error?.status === 503 ? 503 : 500;
      return json(res, status, { error: status === 503 ? error.message : "요청을 처리하지 못했어요. 잠시 후 다시 시도해 주세요." });
    }
  };
}

module.exports = { handler };
