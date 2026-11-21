const corsHeaders = {
  "Access-Control-Allow-Origin": "https://colony-ha.github.io",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== "GET") {
      return Response.json(
        { success: false, message: "Method not allowed" },
        { status: 405, headers: corsHeaders }
      );
    }

    if (url.pathname === "/") {
      return Response.json(
        {
          name: "COLONY LINKS API",
          status: "online",
          version: "1.0.0"
        },
        { headers: corsHeaders }
      );
    }

    if (url.pathname === "/health") {
      try {
        await env.DB.prepare("SELECT 1").first();

        return Response.json(
          {
            success: true,
            api: "online",
            database: "connected",
            storage: env.MEDIA ? "connected" : "not connected"
          },
          { headers: corsHeaders }
        );
      } catch (error) {
        return Response.json(
          {
            success: false,
            api: "online",
            database: "error",
            message: error.message
          },
          { status: 500, headers: corsHeaders }
        );
      }
    }

    return Response.json(
      { success: false, message: "Not found" },
      { status: 404, headers: corsHeaders }
    );
  }
};
