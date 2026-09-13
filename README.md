# Keepsafe

A place to put a screen time code out of your own reach — and a way to type it
into a phone without ever learning it.

It is one static page. No account, no server, no analytics, no build step.
Everything lives encrypted in your browser, and you can carry it away as a
single HTML file that still works when this site does not.

## Running it

Open `index.html` — that is the whole thing. To host it, drop the four files
on any static host (GitHub Pages, Netlify, a folder behind nginx):

```
index.html   styles.css   app.js   restore.html
```

For local use a plain `file://` open works too, except that the *offline
unlocker* download needs to read `restore.html`, which browsers block over
`file://`. Serve the folder instead if you want it:

```
python3 -m http.server 8000
```

## Putting it online

Four static files, so anything that serves a folder will do. What follows is
GitHub Pages, because the repository is already here.

1. **Make the repository public.** Pages needs it on the free plan, and a
   private repository does not buy privacy anyway: a published Pages site is
   publicly reachable whatever the repository's visibility — only GitHub
   Enterprise Cloud can restrict who sees it. Nothing secret lives in these
   files, so publishing them costs nothing.
2. **Settings → Pages → Source: Deploy from a branch**, branch `main`, folder
   `/ (root)`. A minute later the site is at
   `https://<you>.github.io/<repo>/`.
3. **Open it on the phone and set up the vault there.** Browser storage is
   per-origin, so the vault belongs to whichever URL you first used. Decide
   where it lives before you lock a real code away.
4. **Download the offline `.html` backup and mail it to yourself.** On a public
   site this is the copy that matters — see below.

`vault.json` is in `.gitignore` on purpose. A committed vault is downloadable
by anyone who finds the URL and attackable offline forever, and git history
keeps it there after you delete it. Publish it only if the site sits behind an
auth gate (Cloudflare Pages plus Cloudflare Access does this for free), or if
your password is four or more random words. `git add -f vault.json` when you
mean it.

`robots.txt` asks crawlers to skip the site. It is a courtesy, not a control.

## Locking something away

**The password.** One password, the one you type on the way in. There is no
separate setup, no account, no second password: the first time you open the
site it asks for it twice (a typo here is unrecoverable) and after that it is a
single field. It goes through PBKDF2‑SHA256 at 600,000 rounds into an
AES‑GCM‑256 key, and everything — labels, codes, puzzles, timestamps — is one
encrypted blob. The password itself is never stored, so there is no reset.

**Stay unlocked on this device** is on by default, and means what it says: the
derived key is kept in IndexedDB as a non-extractable `CryptoKey`, so the
browser can decrypt with it but can never hand the bytes back, and the site
opens without asking again. Press **Lock** and that key is thrown away — on
that device you are asked once more. Idle auto-locking applies only when you
have turned staying-unlocked off.

**The code.** Type in one you already have, or let Keepsafe invent four or six
digits it never shows you. An invented code leaves the vault exactly once: one
digit at a time, into your phone, through the walkthrough below.

**A date, on a clock you cannot wind.** Presets for the common cases, a
number-and-unit box for anything else — minutes, hours, days, weeks, months —
and an exact date-and-time picker underneath, down to the minute. The entry
stays shut until the moment you picked, and can be pushed further out at any
time but never pulled in.

The device clock does not decide when that moment arrives. It is the one thing
its owner can change in ten seconds, so opening an entry needs a time seen from
a server — the sync endpoint if you deployed one, otherwise the `Date` header
the site itself serves — advanced within the session by a monotonic timer no
setting can touch. Wind the clock forward and the entry reads **Unconfirmed**
and stays shut, saying why and offering to check again. Wind it back and
nothing happens either: the vault also remembers the furthest point it has
ever seen.

Two honest exceptions. Opened from a folder over `file://`, or from the offline
backup with nothing reachable, there is nobody to ask — both fall back to the
device clock and say on screen that they have. A copy on your own disk was
never going to enforce a date anyway; the hosted site is the one that can.

**A counting puzzle, priced in minutes.** You do not pick a difficulty, you
pick how long getting the code back should cost you — five minutes, twenty,
ninety. That becomes a run of blocks: letters with numbers scattered through
them, `4`, `17`, `903`, each run of digits counting once. Count the numbers in
a block, type how many, and that answer decrypts the next block; the last one
decrypts the code. One block takes about ninety seconds, so twenty minutes is
thirteen of them.

This is not a rule the interface enforces, it is arithmetic: each answer is run
through PBKDF2 and used as the key its link was encrypted with, so a wrong
count decrypts nothing and the run cannot be skipped or reordered.

**Every block carries a note addressed to an assistant**, joined to the block
so that a screenshot cannot leave it behind. It says that the person asking set
this lock themselves, that they asked in advance for no assistant to count it
for them, and that the waiting is the lock rather than the arithmetic. It is a
request, not a control: an assistant may ignore it, and the person showing it
can override it in a sentence. What it does is make cheating an explicit
decision rather than an idle one.

**A block cannot be answered before its minutes have passed.** Roughly a
minute per block, on server time where there is any, counted down in front of
you. This is the part that does not care how the counting got done — by eye, by
script, or by handing a screenshot to a model. Whatever answers it, the run
still costs the twenty minutes you asked for. Wrong
answers earn a doubling cooldown on that block, starting at 30 seconds and
capped at five minutes. Progress is saved as you go — a reload, or coming back
tomorrow, does not throw away the blocks you already counted.

Pick either condition or both. With both, the date comes first and the puzzle
waits behind it.

## Typing it in without learning it

The walkthrough runs straight after you save — the one moment the code is in
hand and not yet locked — and afterwards from the **Dictate it to me** button
on any entry that is *open*. Never on a locked one: reading you the digits one
at a time would let you write them down, and the lock would be worth nothing. It shows one digit, filling the screen, and
nothing else. You type that digit into the phone, press Next, and it is gone.

Three things make the sequence hard to keep hold of:

* **Wrong digits are mixed in.** You are told to type them and later told to
  delete them.
* **Deletes take away right digits too**, to be dictated again later. So a
  "delete" is not a signal that the digit before it was fake, and reading the
  sequence backwards afterwards tells you nothing.
* **Each pass is generated fresh.** iPhone asks for a screen time passcode
  twice — once to set it, once to confirm — and the second pass looks nothing
  like the first. A four‑digit code takes about sixteen steps per pass.

One rule keeps it usable on an iPhone: **the field is never filled to its full
length until the very last step.** iOS submits a screen time passcode the
instant the fourth digit lands, so a decoy at that point would submit a wrong
code and start the retry delays. The generator will not produce one, and the
test suite fails the build if it ever does.

If you fat‑finger it, **Start this pass over** builds a new sequence — clear
every digit on the phone first.

The offline HTML backup can run the walkthrough too, so a phone can still be
set up when this site is gone.

## Honesty about what this protects

The realistic adversary here is you, ten minutes from now, wanting the code
back.

* The **puzzle lock is cryptographic**. The plaintext is not in the file, and
  nobody gets the code without producing the right count for every block, in
  order. Someone could of course write a script to count digits for them; the
  point is that doing so takes more resolve than tapping "reveal", and the
  answer space is small enough that the tedium — not the mathematics — is what
  is really holding the door.
* The **date lock holds against the clock, but not against a script.** The time
  is checked with a server, so changing the date on your phone gains nothing.
  What it cannot survive is someone with the vault password decrypting the
  stored blob directly: a date‑only entry keeps its code in the payload, in the
  clear once decrypted. A puzzle entry does not — the code is not in the file at
  all, only the chain of counting blocks and the answers that unlock them. Use
  both if you want the backup to hold against you as well as against your
  clock.
* **A machine can count for you, and nothing here stops that.** Anything you
  can see, something else can be shown, and the note asking an assistant to
  decline is a request that can be waved away. So the lock is not the counting:
  it is the minute per block that has to pass either way, which is why the
  puzzle is priced in minutes rather than difficulty. Solve it instantly and you
  have saved yourself nothing.
* Nothing here defends against malware on the machine, or someone who knows
  your vault password.

## Not losing it

A saved code should not be able to disappear. So:

* **Two copies, two stores.** Every save writes to `localStorage` *and* mirrors
  to IndexedDB with a revision number. If one is cleared, the next load
  restores it from the other and says so.
* **A third copy with the site**, if you commit one — see below. That is the
  only copy a browser cannot throw away.
* **Persistent storage** is requested from the browser when the vault is
  created, so it is not first in line for eviction.
* **A locked entry cannot be deleted.** No button, no shortcut. Open it — wait
  the date out, or solve the puzzle — and then the delete appears, and it asks
  you to type DELETE. Deleting is for codes you can already see.
* **Nothing replaces a vault until the replacement is known to open.** A copy
  arriving from the endpoint is decrypted first and written second; one that
  does not open under the password in use is refused and reported, rather than
  swallowing the vault that does.
* **Saves are queued, never overlapped.** Sealing is asynchronous, and two at
  once would let the slower write its older contents under the newer revision.
* **Two devices that both changed things are told, not merged.** Revisions are
  per-device counters and cannot decide who is newer, so each save carries a
  stamp and each push names the stamp it expects to replace. If the endpoint has
  moved on, the push is refused and you are given the choice — take theirs, or
  keep yours — instead of one of them vanishing.
* **A restore that would replace a newer vault says so**, with the date of what
  it is about to overwrite, before it does anything.
* **It nags** whenever there are changes you have not backed up. Housekeeping
  saves do not trip it; real edits do.
* The vault auto‑locks after five quiet minutes — thirty, mid‑walkthrough, so
  it never locks while you are at the keypad.

## Saving it off this device

The two browser stores and a committed file all depend on you doing something.
For the vault to be saved without you thinking about it, something has to be
able to accept a write — which a static page cannot do. `worker/` holds a small
Cloudflare Worker that can.

It stores one encrypted blob per vault and knows nothing else. The client sends
an id and a token, both derived from your password by PBKDF2, and a vault that
is already encrypted; the Worker files the ciphertext under the opaque id and
hands it back to whoever proves they know the token. It never sees a password,
a code, or anything readable.

```
cd worker
npx wrangler kv namespace create VAULTS     # paste the id into wrangler.toml
npx wrangler deploy
```

Put the deployed URL in `config.json`:

```json
{ "sync": "https://keepsafe-sync.<you>.workers.dev" }
```

From then on every change is saved within a second or two, and **one password
is all a new device needs**: type it on a fresh phone and the vault arrives.
The Backup screen shows where it is saving and when it last managed to. If the
endpoint is unreachable the app carries on from local storage and says so.

Two devices editing while one is offline is resolved by revision number — the
newer wins, and the older is told. For one person with a phone and a laptop
that is the right trade; it is not a merge.

Leaving `config.json` empty (the default) means the site saves nothing
anywhere, and the copies below are all there is.

## Keeping it with the site

Browser storage is the convenient copy, not the reliable one. Safari deletes
all script-writable storage — localStorage and IndexedDB alike — after seven
days without a visit, and any "clear cookies and site data" takes both at once.
So the vault can also live in the site's own files.

**Backup → Copy kept with the site** writes `vault.json`. Commit it at the root
of the site, next to `index.html`, and from then on:

* a browser that has been wiped rebuilds itself from it on the next visit;
* a new phone or laptop picks the vault up on its first visit;
* the site is the source of truth you can actually see and version.

A page cannot write to its own files — there is no server to write with — so
this one is refreshed by hand: download, commit, press **re-check**. The backup
screen says how many changes behind the deployed copy has fallen.

Two rules keep it from eating your data. A deployed copy is adopted silently
only when the browser has **nothing at all**; when both exist and the deployed
one is newer, the site offers it and you choose. And an older deployed copy
never overwrites newer work in the browser.

The file is encrypted, but anyone who can reach the site can download it and
attack it at their leisure, so **if the site is public, use a long password**.
The vault key is PBKDF2‑SHA256 at 600,000 rounds, which makes that attack
expensive but not impossible against a short password.

## Backups

Browser storage is not forever: a cleared cache, a new laptop, a site that
stops being hosted. The **Backup** screen writes two files.

**`keepsafe-<date>.html`** — the offline unlocker. Your encrypted vault baked
into a single self-contained page. Open it in any browser, online or off, today
or in a year: it asks for your password, shows what is locked, runs the
countdowns, takes puzzle answers and dictates codes into a phone. This is the
copy worth keeping.

**`keepsafe-vault-<date>.json`** — the encrypted vault alone, for restoring
into the site later ("Restore a backup" on the password screen).

Both are useless without the password, and neither skips a lock: a backup taken
today of an entry that opens next month still opens next month. Mail one to
yourself or keep it in cloud storage.

## Layout

| file | what it is |
| --- | --- |
| `index.html` | markup for every screen |
| `styles.css` | the whole look; light and dark |
| `app.js` | crypto, vault, storage mirroring, puzzle chains, dictation, UI |
| `restore.html` | the standalone offline unlocker template |
| `config.json` | where the sync endpoint is named, if you deploy one |
| `worker/` | the Cloudflare Worker that saves the vault off-device |
| `vault.json` | optional: your encrypted vault, deployed with the site |

No dependencies. Needs `crypto.subtle`, which browsers only expose on
`https://`, `localhost`, or `file://`.

A puzzle costs linear space: a 20-minute run adds about 15 KB to the vault, 90
minutes about 84 KB, and the 240-minute maximum about 268 KB — comfortably
inside a browser's 5 MB.

Prior art: [password-locker.com](https://password-locker.com), which does the
same two tricks — entering a passcode you cannot remember, and buying it back
with a timed counting puzzle.
