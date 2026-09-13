# Keepsafe

A place to put a screen time code out of your own reach — until a date passes,
until you count your way out, or both.

It is one static page. No account, no server, no analytics, no build step.
Everything lives encrypted in your browser's local storage, and you can carry
it away as a single HTML file that still works when this site does not.

## Running it

Open `index.html` — that is the whole thing. To host it, drop the four files
on any static host (GitHub Pages, Netlify, a folder behind nginx):

```
index.html   styles.css   app.js   restore.html
```

For local use, a plain `file://` open works too, except that the *offline
unlocker* download needs to read `restore.html` and browsers block that over
`file://`. Serve the folder instead if you want it:

```
python3 -m http.server 8000
```

## The three locks

**A password.** Choosing one creates the vault. The password goes through
PBKDF2‑SHA256 (310,000 rounds) into an AES‑GCM‑256 key, and everything —
labels, codes, puzzles, timestamps — is stored as one encrypted blob. The
password is never stored, so there is no reset and no recovery. If you forget
it the vault is gone.

**A date.** The entry stays shut until the moment you picked. It can be pushed
further out at any time; it can never be pulled in. Winding the device clock
back does not help: the vault records the furthest point in time it has ever
seen and counts down from the later of the two.

**A counting puzzle.** A block of letters with numbers scattered through it —
`4`, `17`, `903`, each run of digits counting once. To get your code back you
count them and type how many there were. This one is not a rule the interface
enforces, it is arithmetic: the answer is run through PBKDF2 (600,000 rounds)
and used as the key the code was encrypted with, so a wrong count decrypts to
nothing. Three sizes: light (~22 numbers), medium (~48), heavy (~95). Wrong
answers earn a doubling cooldown, starting at 30 seconds.

Pick either condition or both. With both, the date comes first and the puzzle
waits behind it.

## Honesty about what this protects

The realistic adversary here is you, ten minutes from now, wanting the code
back.

* The **puzzle lock is cryptographic**. The plaintext is not in the file. Nobody
  — not you, not someone with your password, not someone reading local storage
  — gets the code without producing the right count. A determined person could
  of course write a script to count the digits for them; the point is that
  doing so takes more resolve than tapping "reveal".
* The **date lock is a promise the interface keeps**, not a cage. A time lock
  cannot be enforced by cryptography on a machine you control. Anyone who
  knows the vault password and is willing to poke at the stored JSON can read a
  date‑only entry early. Combine it with a puzzle if you want the lock to have
  teeth.
* Deleting an entry destroys the code. It never shows it to you on the way out.
* The vault auto-locks after five quiet minutes.

## Backups

Because a browser's local storage is not forever — a cleared cache, a new
laptop, a site that stops being hosted — the **Backup** screen writes two files:

**`keepsafe-<date>.html`** — the offline unlocker. Your encrypted vault baked
into a single self-contained page. Open it in any browser, online or off,
today or in a year, and it asks for your password, shows what is locked, runs
the countdowns and takes puzzle answers. This is the copy worth keeping.

**`keepsafe-vault-<date>.json`** — the encrypted vault on its own, for
restoring into the site later ("Restore a backup" on the password screen).

Both are useless without the password, and neither skips a lock: a backup taken
today of an entry that opens next month still opens next month. Mail one to
yourself or keep it in cloud storage.

## Layout

| file | what it is |
| --- | --- |
| `index.html` | markup for every screen |
| `styles.css` | the whole look; light and dark |
| `app.js` | crypto, vault, puzzle generation, UI |
| `restore.html` | the standalone offline unlocker template |

No dependencies. Needs `crypto.subtle`, which browsers only expose on
`https://`, `localhost`, or `file://`.
