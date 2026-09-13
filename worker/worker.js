/* Keepsafe sync — a Cloudflare Worker that holds one encrypted blob per vault,
 * and tells the client what time it is, which a phone's own clock cannot be
 * trusted to do when the phone's owner wants a code back early.
 *
 * It never sees a password, a code, or anything readable: the client sends an
 * id and a token, both derived from the password by PBKDF2, and a vault that
 * is already encrypted. The Worker stores ciphertext under an opaque id and
 * hands it back to whoever proves they know the token.
 *
 * Deploy:  cd worker && npx wrangler kv namespace create VAULTS
 *          (paste the id into wrangler.toml, then)  npx wrangler deploy
 */

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400'
};

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS }
  });

async function sha256(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    /* Anyone may ask the time — it is the one thing here worth knowing that is
       not a secret, and a client with no vault yet still needs it. */
    if (new URL(request.url).pathname.replace(/\/+$/, '').endsWith('/time')) {
      return json({ now: Date.now() });
    }

    if (request.method !== 'POST') return json({ error: 'post only' }, 405);
    if (!env.VAULTS) return json({ error: 'no KV namespace bound' }, 500);

    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }

    const id = String(body.id || ''), token = String(body.token || '');
    if (!/^[a-f0-9]{32,128}$/.test(id) || token.length < 32) return json({ error: 'bad credentials' }, 400);

    const slot = 'vault:' + id;
    const stored = await env.VAULTS.get(slot, 'json');
    const tokenHash = await sha256(token);

    /* The first writer claims the slot; after that the token has to match. */
    if (stored && stored.tokenHash !== tokenHash) return json({ error: 'denied' }, 403);

    const path = new URL(request.url).pathname.replace(/\/+$/, '');

    if (path.endsWith('/pull')) {
      return json({ vault: stored ? stored.vault : null, savedAt: stored ? stored.savedAt : null, now: Date.now() });
    }

    if (path.endsWith('/push')) {
      const vault = body.vault;
      if (!vault || vault.v !== 1 || !vault.data || !vault.kdf) return json({ error: 'not a vault' }, 400);
      const size = JSON.stringify(vault).length;
      if (size > 4_000_000) return json({ error: 'vault too large' }, 413);

      /* Revisions are per-device counters: two devices can reach the same number
         holding different vaults, so they cannot decide who is newer. What can
         is the stamp of the vault the client last saw here. If the slot has
         moved on since, the client is told, and nothing is overwritten. */
      if (stored && !body.force) {
        const held = stored.vault.stamp;
        const expect = body.expect;
        const matches = held ? expect === held : (Number(vault.rev) || 0) >= (Number(stored.vault.rev) || 0);
        if (!matches) {
          return json({ ok: false, reason: 'stale', vault: stored.vault, savedAt: stored.savedAt }, 409);
        }
      }

      const savedAt = Date.now();
      await env.VAULTS.put(slot, JSON.stringify({ tokenHash, vault, savedAt }));
      return json({ ok: true, rev: Number(vault.rev) || 0, stamp: vault.stamp || null, savedAt, now: savedAt });
    }

    return json({ error: 'not found' }, 404);
  }
};
