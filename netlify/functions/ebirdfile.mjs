/* Fetches the zip from the link in eBird's "Your eBird data are now available" email, for the person's own browser to read.
   Only eBird's own download files can be fetched. Nothing is saved or logged here, and the reply is never cached. */
export const config = { path: "/ebird-file/:name" };
const NAME = /^ebird_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.zip$/;
const BASE = "https://is-ebird-datadownload-projects-prod.s3.amazonaws.com/download_my_data/";
const MAX = 50e6;
const say = (status, error) => new Response(JSON.stringify({ error }), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
export default async (req, context) => {
  if (req.method !== "GET") return say(405, "Not allowed.");
  const name = (context && context.params && context.params.name) || new URL(req.url).pathname.split("/").pop();
  if (!NAME.test(name)) return say(400, "That isn't an eBird download link.");
  let up;
  try { up = await fetch(BASE + name, { redirect: "error" }); } catch (e) { return say(502, "eBird didn't answer. Try again in a minute."); }
  if (up.status === 403 || up.status === 404) return say(410, "That link has run out. Ask eBird for a fresh file, then paste the new link.");
  if (!up.ok || !up.body) return say(502, "eBird didn't send the file. Try again in a minute.");
  const len = Number(up.headers.get("content-length") || 0);
  if (len > MAX) return say(413, "That file is too big to fetch this way. Download it from the email and choose the file instead.");
  return new Response(up.body, { headers: { "content-type": "application/zip", "cache-control": "no-store, private", ...(len ? { "content-length": String(len) } : {}) } });
};
