export async function onRequest({ request }) {
  const incoming = new URL(request.url);
  const upstream = new URL(incoming.pathname + incoming.search, "https://colony-links-api.colonyus666.workers.dev");
  const forwarded = new Request(upstream.toString(), request);
  return fetch(forwarded);
}
