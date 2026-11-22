import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { APIError } from "better-auth/api";



const ADMIN_EMAILS = new Set(["hanih9823@gmail.com", "colonyus666@gmail.com"]);

const RESERVED_USERNAMES = new Set(["admin","administrator","api","www","signup","login","logout","dashboard","profile","settings","support","help","about","terms","privacy","pricing","billing","assets","static","auth","null","undefined"]);

async function getCurrentSession(auth, request) {
  return auth.api.getSession({ headers: request.headers });
}

const PROFILE_TEMPLATE_LEVELS = { classic: 0, minimal: 0, aurora: 1, glass: 1, signature: 2 };
function canUseProfileTemplate(template, plan) {
  const levels = { free: 0, pro: 1, business: 2 };
  return Object.prototype.hasOwnProperty.call(PROFILE_TEMPLATE_LEVELS, template) &&
    PROFILE_TEMPLATE_LEVELS[template] <= (levels[plan] ?? 0);
}
async function ensureProfileTemplateColumn(env) {
  const columns = await env.DB.prepare("PRAGMA table_info(profiles)").all();
  if (!(columns.results || []).some(column => column.name === "template_key")) {
    try {
      await env.DB.prepare("ALTER TABLE profiles ADD COLUMN template_key TEXT NOT NULL DEFAULT 'classic'").run();
    } catch (error) {
      if (!String(error?.message || "").toLowerCase().includes("duplicate column")) throw error;
    }
  }
}

function isAdminUser(user) {
  return ADMIN_EMAILS.has(String(user?.email || "").trim().toLowerCase());
}

async function getEffectiveAccess(env, user) {
  // Administrators bypass all subscription checks and feature limits.
  if (isAdminUser(user)) {
    return { plan: "business", unlimited: true, isAdmin: true };
  }

  const subscription = await env.DB.prepare(
    "SELECT plan FROM subscriptions WHERE user_id = ? AND status = 'active' AND julianday(ends_at) > julianday('now') ORDER BY julianday(ends_at) DESC, created_at DESC LIMIT 1"
  ).bind(user.id).first();

  return {
    plan: subscription?.plan || "free",
    unlimited: false,
    isAdmin: false
  };
}

async function handleAdminRoutes(request, env, url) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_user_status (user_id TEXT PRIMARY KEY NOT NULL, is_disabled INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE)`).run();
  const auth = createAuth(env);
  const session = await getCurrentSession(auth, request);
  if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);

  const email = String(session.user.email || "").trim().toLowerCase();
  if (!ADMIN_EMAILS.has(email)) return json({ success: false, message: "Forbidden" }, 403);

  if (url.pathname === "/api/admin/me" && request.method === "GET") {
    return json({ success: true, isAdmin: true, admin: { name: session.user.name || "", email } });
  }

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL, plan TEXT NOT NULL CHECK(plan IN ('free','pro','business')), status TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL DEFAULT 'admin_free', starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', granted_by TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE)`).run();
  if (url.pathname === "/api/admin/subscriptions" && request.method === "GET") {
    await env.DB.prepare("UPDATE subscriptions SET status = 'expired' WHERE status = 'active' AND julianday(ends_at) <= julianday('now')").run();
    const result = await env.DB.prepare("SELECT subscriptions.*, user.email, user.name FROM subscriptions JOIN user ON user.id = subscriptions.user_id ORDER BY subscriptions.created_at DESC LIMIT 200").all();
    return json({ success: true, subscriptions: result.results || [] });
  }
  if (url.pathname === "/api/admin/subscriptions/grant" && request.method === "POST") {
    let body; try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON" }, 400); }
    const email = String(body.email || "").trim().toLowerCase();
    const plan = String(body.plan || "").toLowerCase();
    const months = Number(body.months);
    const reason = String(body.reason || "").trim().slice(0, 180);
    if (!email || !["free","pro","business"].includes(plan) || !Number.isInteger(months) || months < 1 || months > 12) return json({ success: false, message: "Enter a valid account, plan and duration (1–12 months)." }, 400);
    const target = await env.DB.prepare("SELECT id FROM user WHERE lower(email) = ?").bind(email).first();
    if (!target) return json({ success: false, message: "Account not found." }, 404);
    const starts = new Date(); const ends = new Date(starts); ends.setMonth(ends.getMonth() + months);
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO subscriptions (id,user_id,plan,status,source,starts_at,ends_at,reason,granted_by) VALUES (?,?,?,'active','admin_free',?,?,?,?)").bind(id,target.id,plan,starts.toISOString(),ends.toISOString(),reason,session.user.id).run();
    return json({ success: true, subscription: { id, email, plan, starts_at: starts.toISOString(), ends_at: ends.toISOString(), source: "admin_free" } });
  }
  if (url.pathname === "/api/admin/users" && request.method === "GET") {
    const query = String(url.searchParams.get("q") || "").trim().slice(0, 100);
    const page = Math.max(1, Math.min(10000, Number.parseInt(url.searchParams.get("page") || "1", 10) || 1));
    const limit = 25;
    const offset = (page - 1) * limit;
    const pattern = "%" + query + "%";
    const where = query ? "WHERE name LIKE ? OR email LIKE ?" : "";
    const countQuery = "SELECT COUNT(*) AS total FROM user " + where;
    const usersQuery = "SELECT user.id, user.name, user.email, user.createdAt, COALESCE(admin_user_status.is_disabled, 0) AS isDisabled FROM user LEFT JOIN admin_user_status ON admin_user_status.user_id = user.id " + where.replace(/\bname\b/g, "user.name").replace(/\bemail\b/g, "user.email") + " ORDER BY user.createdAt DESC LIMIT ? OFFSET ?";
    const countStatement = env.DB.prepare(countQuery);
    const usersStatement = env.DB.prepare(usersQuery);
    const count = query ? await countStatement.bind(pattern, pattern).first() : await countStatement.first();
    const users = query
      ? await usersStatement.bind(pattern, pattern, limit, offset).all()
      : await usersStatement.bind(limit, offset).all();
    return json({ success: true, users: users.results || [], total: count?.total || 0, page, limit });
  }

  const userMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (userMatch && request.method === "PUT") {
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON" }, 400); }
    const name = String(body.name || "").trim().slice(0, 80);
    if (!name) return json({ success: false, message: "Name is required." }, 400);
    const userId = decodeURIComponent(userMatch[1]);
    const target = await env.DB.prepare("SELECT id, email FROM user WHERE id = ?").bind(userId).first();
    if (!target) return json({ success: false, message: "User not found." }, 404);
    if (ADMIN_EMAILS.has(String(target.email || "").trim().toLowerCase())) return json({ success: false, message: "Administrator accounts cannot be edited here." }, 403);
    await env.DB.prepare("UPDATE user SET name = ?, updatedAt = ? WHERE id = ?").bind(name, new Date().toISOString(), userId).run();
    return json({ success: true, user: { id: userId, name } });
  }

  const statusMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)\/status$/);
  if (statusMatch && request.method === "PUT") {
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON" }, 400); }
    const userId = decodeURIComponent(statusMatch[1]);
    const disabled = body.disabled === true;
    if (userId === session.user.id || ADMIN_EMAILS.has(String((await env.DB.prepare("SELECT email FROM user WHERE id = ?").bind(userId).first())?.email || "").trim().toLowerCase())) {
      return json({ success: false, message: "Administrator accounts cannot be disabled." }, 403);
    }
    const target = await env.DB.prepare("SELECT id FROM user WHERE id = ?").bind(userId).first();
    if (!target) return json({ success: false, message: "User not found." }, 404);
    await env.DB.prepare("INSERT INTO admin_user_status (user_id, is_disabled, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET is_disabled = excluded.is_disabled, updated_at = CURRENT_TIMESTAMP").bind(userId, disabled ? 1 : 0).run();
    if (disabled) await env.DB.prepare("DELETE FROM session WHERE userId = ?").bind(userId).run();
    return json({ success: true, isDisabled: disabled });
  }

  if (userMatch && request.method === "DELETE") {
    const userId = decodeURIComponent(userMatch[1]);
    if (userId === session.user.id) return json({ success: false, message: "You cannot delete your own administrator account." }, 403);
    const target = await env.DB.prepare("SELECT id, email FROM user WHERE id = ?").bind(userId).first();
    if (!target) return json({ success: false, message: "User not found." }, 404);
    if (ADMIN_EMAILS.has(String(target.email || "").trim().toLowerCase())) return json({ success: false, message: "Administrator accounts are protected from deletion." }, 403);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM profile_links WHERE user_id = ?").bind(userId),
      env.DB.prepare("DELETE FROM profiles WHERE user_id = ?").bind(userId),
      env.DB.prepare("DELETE FROM session WHERE userId = ?").bind(userId),
      env.DB.prepare("DELETE FROM account WHERE userId = ?").bind(userId),
      env.DB.prepare("DELETE FROM user WHERE id = ?").bind(userId)
    ]);
    return json({ success: true });
  }

  return json({ success: false, message: "Not found" }, 404);
}

async function handleProfileRoutes(request, env, url) {
  const auth = createAuth(env);
  if (url.pathname === "/api/profile/me" || url.pathname.startsWith("/api/public/profile/")) await ensureProfileTemplateColumn(env);

  if (url.pathname === "/api/profile/avatar" && request.method === "POST") {
    const session = await getCurrentSession(createAuth(env), request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    const form = await request.formData();
    const file = form.get("avatar");
    if (!file || typeof file.arrayBuffer !== "function") return json({ success: false, message: "Choose an image first." }, 400);
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.type)) return json({ success: false, message: "Use a JPG, PNG or WebP image." }, 400);
    if (file.size > 2 * 1024 * 1024) return json({ success: false, message: "Image must be 2 MB or smaller." }, 413);
    const extension = file.type === "image/jpeg" ? "jpg" : file.type === "image/png" ? "png" : "webp";
    const key = "avatars/" + session.user.id + "/" + crypto.randomUUID() + "." + extension;
    await env.MEDIA.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type, cacheControl: "public, max-age=86400" } });
    await env.DB.prepare("UPDATE profiles SET avatar_key = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?").bind(key, session.user.id).run();
    return json({ success: true, avatarUrl: "/api/media/avatar/" + encodeURIComponent(key) });
  }

  const mediaMatch = url.pathname.match(/^\/api\/media\/avatar\/(.+)$/);
  if (mediaMatch && request.method === "GET") {
    const key = decodeURIComponent(mediaMatch[1]);
    if (!key.startsWith("avatars/") || key.includes("..")) return json({ success: false, message: "Not found" }, 404);
    const object = await env.MEDIA.get(key);
    if (!object) return json({ success: false, message: "Not found" }, 404);
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("Cache-Control", "public, max-age=86400");
    headers.set("X-Content-Type-Options", "nosniff");
    return new Response(object.body, { headers });
  }

  if (url.pathname === "/api/profile/access" && request.method === "GET") {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    const access = await getEffectiveAccess(env, session.user);
    return json({ success: true, access });
  }

  if (url.pathname === "/api/profile/stats" && request.method === "GET") {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS profile_visitors (
      user_id TEXT NOT NULL,
      visitor_hash TEXT NOT NULL,
      visit_date TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, visitor_hash, visit_date),
      FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )`).run();
    const userId = session.user.id;
    const todayAlgiers = new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Algiers", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
    const stats = await env.DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM profile_links WHERE user_id = ?) AS links_created,
        COALESCE((SELECT SUM(clicks) FROM profile_links WHERE user_id = ?), 0) AS link_clicks,
        COALESCE((SELECT page_views FROM profiles WHERE user_id = ?), 0) AS page_views,
        (SELECT COUNT(DISTINCT visitor_hash) FROM profile_visitors WHERE user_id = ? AND visit_date = ?) AS visitors_today,
        (SELECT COUNT(DISTINCT visitor_hash) FROM profile_visitors WHERE user_id = ? AND visit_date >= date(?, '-29 days')) AS unique_visitors_30d`
    ).bind(userId,userId,userId,userId,todayAlgiers,userId,todayAlgiers).first();
    const daily = await env.DB.prepare(
      `SELECT visit_date AS date, COUNT(*) AS visitors FROM profile_visitors
       WHERE user_id = ? AND visit_date >= date(?, '-29 days')
       GROUP BY visit_date ORDER BY visit_date ASC`
    ).bind(userId,todayAlgiers).all();
    const topLinks = await env.DB.prepare(
      `SELECT title, clicks FROM profile_links WHERE user_id = ? ORDER BY clicks DESC, created_at ASC LIMIT 5`
    ).bind(userId).all();
    return json({ success: true, stats: stats || {}, daily: daily.results || [], top_links: topLinks.results || [] });
  }

  if (url.pathname.startsWith("/api/public/click/") && request.method === "GET") {
    const clickMatch = url.pathname.match(/^\/api\/public\/click\/([a-zA-Z0-9-]+)$/);
    if (!clickMatch) return json({ success: false, message: "Not found" }, 404);
    const link = await env.DB.prepare("SELECT url FROM profile_links WHERE id = ? AND is_active = 1").bind(clickMatch[1]).first();
    if (!link) return json({ success: false, message: "Link not found" }, 404);
    await env.DB.prepare("UPDATE profile_links SET clicks = clicks + 1 WHERE id = ?").bind(clickMatch[1]).run();
    return Response.redirect(link.url, 302);
  }

  if (url.pathname === "/api/profile/links" && request.method === "GET") {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    const result = await env.DB.prepare(
      "SELECT id, title, url, sort_order, is_active, created_at FROM profile_links WHERE user_id = ? ORDER BY sort_order ASC, created_at ASC"
    ).bind(session.user.id).all();
    return json({ success: true, links: result.results || [] });
  }

  if (url.pathname === "/api/profile/links" && request.method === "POST") {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON" }, 400); }
    const title = String(body.title || "").trim().slice(0, 60);
    const rawUrl = String(body.url || "").trim().slice(0, 2048);
    let parsedUrl;
    try { parsedUrl = new URL(rawUrl); } catch { return json({ success: false, message: "Enter a valid URL beginning with https:// or http://." }, 400); }
    if (!title) return json({ success: false, message: "Link title is required." }, 400);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) return json({ success: false, message: "Only HTTP and HTTPS links are allowed." }, 400);
    const id = crypto.randomUUID();
    const order = await env.DB.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next_order FROM profile_links WHERE user_id = ?").bind(session.user.id).first();
    await env.DB.prepare(
      "INSERT INTO profile_links (id, user_id, title, url, sort_order, is_active) VALUES (?, ?, ?, ?, ?, 1)"
    ).bind(id, session.user.id, title, parsedUrl.href, order?.next_order ?? 0).run();
    const link = await env.DB.prepare("SELECT id, title, url, sort_order, is_active FROM profile_links WHERE id = ? AND user_id = ?").bind(id, session.user.id).first();
    return json({ success: true, link }, 201);
  }

  const linkMatch = url.pathname.match(/^\/api\/profile\/links\/([a-zA-Z0-9-]+)$/);
  if (linkMatch && (request.method === "PUT" || request.method === "DELETE")) {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    const id = linkMatch[1];
    if (request.method === "DELETE") {
      const result = await env.DB.prepare("DELETE FROM profile_links WHERE id = ? AND user_id = ?").bind(id, session.user.id).run();
      if (!result.meta?.changes) return json({ success: false, message: "Link not found." }, 404);
      return json({ success: true });
    }
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON" }, 400); }
    const title = String(body.title || "").trim().slice(0, 60);
    const rawUrl = String(body.url || "").trim().slice(0, 2048);
    let parsedUrl;
    try { parsedUrl = new URL(rawUrl); } catch { return json({ success: false, message: "Enter a valid URL beginning with https:// or http://." }, 400); }
    if (!title) return json({ success: false, message: "Link title is required." }, 400);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) return json({ success: false, message: "Only HTTP and HTTPS links are allowed." }, 400);
    const result = await env.DB.prepare("UPDATE profile_links SET title = ?, url = ? WHERE id = ? AND user_id = ?").bind(title, parsedUrl.href, id, session.user.id).run();
    if (!result.meta?.changes) return json({ success: false, message: "Link not found." }, 404);
    const link = await env.DB.prepare("SELECT id, title, url, sort_order, is_active FROM profile_links WHERE id = ? AND user_id = ?").bind(id, session.user.id).first();
    return json({ success: true, link });
  }

  if (url.pathname === "/api/profile/me" && request.method === "GET") {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);
    const profile = await env.DB.prepare(
      "SELECT username, display_name, bio, avatar_key, background_color, accent_color, background_style, template_key, created_at, updated_at FROM profiles WHERE user_id = ?"
    ).bind(session.user.id).first();
    return json({ success: true, profile: profile ? { ...profile, avatarUrl: profile.avatar_key ? "/api/media/avatar/" + encodeURIComponent(profile.avatar_key) : "" } : null });
  }

  if (url.pathname === "/api/profile/me" && request.method === "POST") {
    const session = await getCurrentSession(auth, request);
    if (!session?.user) return json({ success: false, message: "Unauthorized" }, 401);

    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON" }, 400); }

    const username = String(body.username || "").trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9_]{2,23}$/.test(username)) {
      return json({ success: false, message: "Username must be 3–24 characters and use lowercase letters, numbers or underscores." }, 400);
    }
    if (RESERVED_USERNAMES.has(username)) {
      return json({ success: false, message: "This username is reserved. Please choose another one." }, 409);
    }

    const displayName = String(body.displayName || session.user.name || "").trim().slice(0, 60);
    const bio = String(body.bio || "").trim().slice(0, 160);
    const backgroundColor = /^#[0-9a-fA-F]{6}$/.test(body.backgroundColor || "") ? body.backgroundColor : "#090909";
    const accentColor = /^#[0-9a-fA-F]{6}$/.test(body.accentColor || "") ? body.accentColor : "#d6b45b";
    const backgroundStyle = ["glow", "plain", "gradient"].includes(body.backgroundStyle) ? body.backgroundStyle : "glow";
    const templateKey = ["classic","minimal","aurora","glass","signature"].includes(body.templateKey) ? body.templateKey : "classic";
    const access = await getEffectiveAccess(env, session.user);
    if (!canUseProfileTemplate(templateKey, access.plan)) {
      return json({ success: false, message: "This design is available on a higher plan. Upgrade your plan to use it." }, 403);
    }
    try {
      await env.DB.prepare(
        `INSERT INTO profiles (user_id, username, display_name, bio, background_color, accent_color, background_style, template_key, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
         ON CONFLICT(user_id) DO UPDATE SET
           username = excluded.username,
           display_name = excluded.display_name,
           bio = excluded.bio,
           background_color = excluded.background_color,
           accent_color = excluded.accent_color,
           background_style = excluded.background_style,
           template_key = excluded.template_key,
           updated_at = CURRENT_TIMESTAMP`
      ).bind(session.user.id, username, displayName, bio, backgroundColor, accentColor, backgroundStyle, templateKey).run();

      const profile = await env.DB.prepare(
        "SELECT username, display_name, bio, avatar_key, background_color, accent_color, background_style, template_key, created_at, updated_at FROM profiles WHERE user_id = ?"
      ).bind(session.user.id).first();
      return json({ success: true, profile: { ...profile, avatarUrl: profile.avatar_key ? "/api/media/avatar/" + encodeURIComponent(profile.avatar_key) : "" } });
    } catch (error) {
      const message = String(error?.message || "");
      if (message.toLowerCase().includes("unique")) {
        return json({ success: false, message: "This username is already taken. Try another one." }, 409);
      }
      return json({ success: false, message: "Could not save your profile. Please try again." }, 500);
    }
  }

  const publicMatch = url.pathname.match(/^\/api\/public\/profile\/([a-z0-9_]{3,24})$/);
  if (publicMatch && request.method === "GET") {
    const username = publicMatch[1].toLowerCase();
    const profile = await env.DB.prepare(
      "SELECT username, display_name, bio, avatar_key, background_color, accent_color, background_style, template_key, user_id FROM profiles WHERE username = ?"
    ).bind(username).first();
    if (!profile) return json({ success: false, message: "Profile not found" }, 404);
    const { user_id: ownerId, ...publicProfile } = profile;
    const owner = await env.DB.prepare("SELECT id, email FROM user WHERE id = ?").bind(ownerId).first();
    const ownerAccess = await getEffectiveAccess(env, owner || {});
    if (!canUseProfileTemplate(profile.template_key || "classic", ownerAccess.plan)) profile.template_key = "classic";
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS profile_visitors (
      user_id TEXT NOT NULL,
      visitor_hash TEXT NOT NULL,
      visit_date TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, visitor_hash, visit_date),
      FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )`).run();
    const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const agent = request.headers.get("User-Agent") || "unknown";
    const visitorHashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(env.BETTER_AUTH_SECRET || "") + "|" + ip + "|" + agent));
    const visitorHash = Array.from(new Uint8Array(visitorHashBuffer), byte => byte.toString(16).padStart(2,"0")).join("");
    const visitDate = new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Algiers', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
    const inserted = await env.DB.prepare(
      "INSERT OR IGNORE INTO profile_visitors (user_id, visitor_hash, visit_date) VALUES (?,?,?)"
    ).bind(ownerId, visitorHash, visitDate).run();
    if (Number(inserted.meta?.changes || 0) > 0) {
      await env.DB.prepare("UPDATE profiles SET page_views = page_views + 1 WHERE user_id = ?").bind(ownerId).run();
    }
    const links = await env.DB.prepare(
      "SELECT id, title, url FROM profile_links WHERE user_id = (SELECT user_id FROM profiles WHERE username = ?) AND is_active = 1 ORDER BY sort_order ASC, created_at ASC"
    ).bind(username).all();
    return json({ success: true, profile: { ...publicProfile, avatarUrl: publicProfile.avatar_key ? "/api/media/avatar/" + encodeURIComponent(publicProfile.avatar_key) : "" }, links: links.results || [] });
  }

  return null;
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://links.colony.dpdns.org",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Credentials": "true",
};

function json(data, status = 200) {
  return Response.json(data, { status, headers: corsHeaders });
}

function createAuth(env) {
  return betterAuth({
    database: env.DB,
    secret: env.BETTER_AUTH_SECRET,
    databaseHooks: {
      session: {
        create: {
          before: async (session) => {
            const status = await env.DB.prepare("SELECT is_disabled FROM admin_user_status WHERE user_id = ?").bind(session.userId).first();
            if (status?.is_disabled) {
              throw new APIError("FORBIDDEN", { message: "This account has been disabled. Contact support." });
            }
            // Every account receives the permanent Free plan the first time it signs in.
            // Never replace an existing paid, gifted, or expired subscription history.
            await env.DB.prepare(
              "INSERT INTO subscriptions (id,user_id,plan,status,source,starts_at,ends_at,reason,granted_by) SELECT ?,?,'free','active','system_default',?, '9999-12-31T23:59:59.999Z','Default free plan','system' WHERE NOT EXISTS (SELECT 1 FROM subscriptions WHERE user_id = ?)"
            ).bind(crypto.randomUUID(), session.userId, new Date().toISOString(), session.userId).run();
            return { data: session };
          }
        }
      }
    },
    baseURL: env.BETTER_AUTH_URL || "https://links.colony.dpdns.org",
    basePath: "/api/auth",
    trustedOrigins: [
      "https://links.colony.dpdns.org",
      "https://colony-links.pages.dev"
    ],
    emailAndPassword: {
      enabled: true
    },
    socialProviders: env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET ? {
      google: {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        prompt: "select_account"
      }
    } : {},
    advanced: {
      ipAddress: {
        ipAddressHeaders: ["cf-connecting-ip"]
      }
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (url.pathname === "/") {
      return json({
        name: "COLONY LINKS API",
        status: "online",
        version: "1.1.0",
        authentication: "configured"
      });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      try {
        await env.DB.prepare("SELECT 1").first();
        return json({
          success: true,
          api: "online",
          database: "connected",
          storage: env.MEDIA ? "connected" : "not connected"
        });
      } catch (error) {
        return json({
          success: false,
          api: "online",
          database: "error",
          message: error.message
        }, 500);
      }
    }

    if (url.pathname === "/api/__admin/migrate" && request.method === "POST") {
      const authorization = request.headers.get("Authorization") || "";
      if (!env.BETTER_AUTH_SECRET || authorization !== `Bearer ${env.BETTER_AUTH_SECRET}`) {
        return json({ success: false, message: "Unauthorized" }, 401);
      }

      try {
        const auth = createAuth(env);        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS profiles (
            user_id TEXT PRIMARY KEY NOT NULL,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            bio TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
          )
        `).run();
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS profile_links (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            clicks INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
          )
        `).run();
        const linkColumns = await env.DB.prepare("PRAGMA table_info(profile_links)").all();
        const existingLinkColumns = new Set((linkColumns.results || []).map((column) => column.name));
        if (!existingLinkColumns.has("clicks")) {
          await env.DB.prepare("ALTER TABLE profile_links ADD COLUMN clicks INTEGER NOT NULL DEFAULT 0").run();
        }
        const currentProfileColumns = await env.DB.prepare("PRAGMA table_info(profiles)").all();
        const currentProfileColumnNames = new Set((currentProfileColumns.results || []).map((column) => column.name));
        if (!currentProfileColumnNames.has("page_views")) {
          await env.DB.prepare("ALTER TABLE profiles ADD COLUMN page_views INTEGER NOT NULL DEFAULT 0").run();
        }
        const profileColumns = await env.DB.prepare("PRAGMA table_info(profiles)").all();
        const existingProfileColumns = new Set((profileColumns.results || []).map((column) => column.name));
        const profileAdditions = [
          ["avatar_key", "TEXT NOT NULL DEFAULT ''"],
          ["background_color", "TEXT NOT NULL DEFAULT '#090909'"],
          ["accent_color", "TEXT NOT NULL DEFAULT '#d6b45b'"],
          ["background_style", "TEXT NOT NULL DEFAULT 'glow'"]
        ];
        for (const [column, definition] of profileAdditions) {
          if (!existingProfileColumns.has(column)) {
            await env.DB.prepare("ALTER TABLE profiles ADD COLUMN " + column + " " + definition).run();
          }
        }
        await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_profiles_username ON profiles(username)").run();
        await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_profile_links_user ON profile_links(user_id, sort_order)").run();

        const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(auth.options);
        if (toBeCreated.length === 0 && toBeAdded.length === 0) {
          return json({ success: true, message: "No migrations needed" });
        }
        await runMigrations();
        return json({
          success: true,
          message: "Authentication database tables created",
          created: toBeCreated.map((item) => item.table),
          updated: toBeAdded.map((item) => item.table)
        });
      } catch (error) {
        return json({
          success: false,
          message: error instanceof Error ? error.message : "Migration failed"
        }, 500);
      }
    }

    if (url.pathname.startsWith("/api/admin/")) {
      try {
        const response = await handleAdminRoutes(request, env, url);
        if (response) return response;
      } catch (error) {
        return json({ success: false, message: "Admin service error" }, 500);
      }
    }

    if (url.pathname.startsWith("/api/profile/") || url.pathname.startsWith("/api/public/profile/") || url.pathname.startsWith("/api/public/click/") || url.pathname.startsWith("/api/media/")) {
      try {
        const response = await handleProfileRoutes(request, env, url);
        if (response) return response;
      } catch (error) {
        return json({ success: false, message: "Profile service error" }, 500);
      }
    }

    if (url.pathname.startsWith("/api/auth/")) {
      try {
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_user_status (user_id TEXT PRIMARY KEY NOT NULL, is_disabled INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE)`).run();
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL, plan TEXT NOT NULL CHECK(plan IN ('free','pro','business')), status TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL DEFAULT 'admin_free', starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', granted_by TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE)`).run();
        const auth = createAuth(env);
        return await auth.handler(request);
      } catch (error) {
        return json({
          success: false,
          message: error instanceof Error ? error.message : "Authentication error"
        }, 500);
      }
    }

    return json({ success: false, message: "Not found" }, 404);
  }
};
