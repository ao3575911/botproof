// web = { gists: {id: {owner, content}}, users: {login: {created_at}}, pages: {url: string | {body, headers}} }
export const fakeFetch = (web) => async (url) => {
  const u = String(url);
  const g = u.match(/^https:\/\/api\.github\.com\/gists\/(\w+)$/);
  if (g) {
    const x = web.gists[g[1]];
    return x ? new Response(JSON.stringify({ owner: { login: x.owner }, files: { "p.txt": { content: x.content } } })) : new Response("{}", { status: 404 });
  }
  const us = u.match(/^https:\/\/api\.github\.com\/users\/([\w-]+)$/);
  if (us) { const x = web.users?.[us[1].toLowerCase()]; return x ? new Response(JSON.stringify(x)) : new Response("{}", { status: 404 }); }
  const p = web.pages[u];
  if (p === undefined) return new Response("not found", { status: 404 });
  return typeof p === "string" ? new Response(p) : new Response(p.body, { headers: p.headers });
};
