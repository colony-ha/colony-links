import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://links.colony.dpdns.org",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
        const auth = createAuth(env);
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
