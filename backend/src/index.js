import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";



const RESERVED_USERNAMES = new Set(["admin","administrator","api","www","signup","login","logout","dashboard","profile","settings","support","help","about","terms","privacy","pricing","billing","assets","static","auth","null","undefined"]);

async function getCurrentSession(auth, request) {
  return auth.api.getSession({ headers: request.headers });
}

async function handleProfileRoutes(request, env, url) {
  const auth = createAuth(env);

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
      "SELECT username, display_name, bio, avatar_key, background_color, accent_color, background_style, created_at, updated_at FROM profiles WHERE user_id = ?"
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
    try {
      await env.DB.prepare(
        `INSERT INTO profiles (user_id, username, display_name, bio, background_color, accent_color, background_style, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
         ON CONFLICT(user_id) DO UPDATE SET
           username = excluded.username,
           display_name = excluded.display_name,
           bio = excluded.bio,
           background_color = excluded.background_color,
           accent_color = excluded.accent_color,
           background_style = excluded.background_style,
           updated_at = CURRENT_TIMESTAMP`
      ).bind(session.user.id, username, displayName, bio, backgroundColor, accentColor, backgroundStyle).run();

      const profile = await env.DB.prepare(
        "SELECT username, display_name, bio, avatar_key, background_color, accent_color, background_style, created_at, updated_at FROM profiles WHERE user_id = ?"
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
      "SELECT username, display_name, bio, avatar_key, background_color, accent_color, background_style FROM profiles WHERE username = ?"
    ).bind(username).first();
    if (!profile) return json({ success: false, message: "Profile not found" }, 404);
    const links = await env.DB.prepare(
      "SELECT id, title, url FROM profile_links WHERE user_id = (SELECT user_id FROM profiles WHERE username = ?) AND is_active = 1 ORDER BY sort_order ASC, created_at ASC"
    ).bind(username).all();
    return json({ success: true, profile: { ...profile, avatarUrl: profile.avatar_key ? "/api/media/avatar/" + encodeURIComponent(profile.avatar_key) : "" }, links: links.results || [] });
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
    baseURL: env.BETTER_AUTH_URL || "https://links.colony.dpdns.org",
    basePath: "/api/auth",
    trustedOrigins: [
      "https://links.colony.dpdns.org",
      "https://colony-links.pages.dev"
    ],
    emailAndPassword: {
      enabled: true
    },
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
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
          )
        `).run();
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

    if (url.pathname.startsWith("/api/profile/") || url.pathname.startsWith("/api/public/profile/")) {
      try {
        const response = await handleProfileRoutes(request, env, url);
        if (response) return response;
      } catch (error) {
        return json({ success: false, message: "Profile service error" }, 500);
      }
    }

    if (url.pathname.startsWith("/api/auth/")) {
      try {
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
