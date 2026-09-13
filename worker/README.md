# Keepsafe sync

A Cloudflare Worker that holds one encrypted blob per vault, so the vault is
saved somewhere a browser cannot throw away.

It never sees a password, a code, or anything readable. The site sends an id
and a token, both derived from your password by PBKDF2, and a vault that is
already encrypted. The Worker files the ciphertext under the opaque id and
hands it back to whoever proves they know the token. That is the whole job.

## Deploying it

You need a computer with Node 18 or newer — this part cannot be done from a
phone — and a free Cloudflare account (`dash.cloudflare.com/sign-up`).

```sh
git clone https://github.com/mem-ro/test1.git
cd test1/worker

npx wrangler login                          # opens a browser, click Allow
npx wrangler kv namespace create VAULTS     # older wrangler: kv:namespace create
```

That prints a block like:

```toml
[[kv_namespaces]]
binding = "VAULTS"
id = "9f2c1e7a5b0d4f3e8a6c2b1d0e9f8a7b"
```

Copy the `id` into `wrangler.toml`, replacing `PASTE_YOUR_KV_NAMESPACE_ID_HERE`.
(Newer wrangler can do it for you: add `--update-config` to the command above.)

```sh
npx wrangler deploy
```

The first deploy on a new account asks you to pick a `workers.dev` subdomain.
When it finishes it prints the URL:

```
https://keepsafe-sync.<your-subdomain>.workers.dev
```

## Pointing the site at it

Put that URL in `config.json` at the root of the repository:

```json
{ "sync": "https://keepsafe-sync.<your-subdomain>.workers.dev" }
```

Commit and push. GitHub Pages redeploys in a minute or so.

## Checking it works

From a terminal — an unknown id should come back empty rather than erroring:

```sh
curl -s -X POST https://keepsafe-sync.<you>.workers.dev/pull \
  -H 'content-type: application/json' \
  -d '{"id":"00000000000000000000000000000000","token":"'"$(printf 'x%.0s' {1..44})"'"}'
```

```json
{"vault":null,"savedAt":null}
```

Then in the app: **Backup** should read *Saving to …workers.dev — saved*. The
real test is a second device: open the site somewhere else, type the same
password, and your vault should be there without restoring anything.

## What it costs

Nothing, at this size. Each change to the vault is one KV write and opening the
app is one read; the free tier's daily allowances are orders of magnitude above
that. A vault is a few kilobytes, or a few hundred with a long counting puzzle.

## The API

Both endpoints are `POST` with a JSON body of `{ id, token, … }`.

| path | body | answer |
| --- | --- | --- |
| `/pull` | — | `{ vault, savedAt }`, `vault: null` if the slot is empty |
| `/push` | `vault`, optional `force` | `{ ok: true, rev, savedAt }` |

`403` means the token does not match the slot — someone else's vault, or your
own under a different password. `409` means what you pushed is older than what
is stored; the stored vault comes back with it so the client can catch up.
