export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const match = url.pathname.match(/^\/@([a-z0-9_]{3,24})\/?$/i);

  if (match && request.method === "GET") {
    const target = new URL("/profile.html", url.origin);
    target.searchParams.set("username", match[1].toLowerCase());
    return context.next(new Request(target.toString(), request));
  }

  return context.next();
}
