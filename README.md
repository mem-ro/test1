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

## Locking something away

**The password.** Choosing one creates the vault. It goes through PBKDF2‑SHA256
(310,000 rounds) into an AES‑GCM‑256 key, and everything — labels, codes,
puzzles, timestamps — is stored as one encrypted blob. The password itself is
never stored, so there is no reset and no recovery.

**The code.** Type in one you already have, or let Keepsafe invent four or six
digits it never shows you. An invented code leaves the vault exactly once: one
digit at a time, into your phone, through the walkthrough below.

**A date.** The entry stays shut until the moment you picked. It can be pushed
further out at any time; it can never be pulled in. Winding the device clock
back does not help — the vault records the furthest point in time it has ever
seen and counts down from the later of the two.

**A counting puzzle.** A block of letters with numbers scattered through it —
`4`, `17`, `903`, each run of digits counting once. To get the code back you
count them and type how many there were. This one is not a rule the interface
enforces, it is arithmetic: the answer is run through PBKDF2 (600,000 rounds)
and used as the key the code was encrypted with, so a wrong count decrypts to
nothing. Light (~22 numbers), medium (~48), heavy (~95). Wrong answers earn a
doubling cooldown, starting at 30 seconds.

Pick either condition or both. With both, the date comes first and the puzzle
waits behind it.

## Typing it in without learning it

The walkthrough runs straight after you save, and afterwards from the entry's
**Dictate it to me** button. It shows one digit, filling the screen, and
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
  nobody gets the code without producing the right count. Someone could of
  course write a script to count the digits for them; the point is that it
  takes more resolve than tapping "reveal".
* The **date lock is a promise the interface keeps**, not a cage. A time lock
  cannot be enforced by cryptography on a machine you control. Anyone who knows
  the vault password and is willing to poke at the stored JSON can read a
  date‑only entry early. Combine it with a puzzle if you want teeth.
* **Guided entry keeps a readable copy.** Dictating a locked code means the app
  can read it, so the copy sits in the vault under your password. The locks
  still keep the code off your screen; they no longer keep it from someone
  digging through storage with the password in hand. Turn the option off when
  you create an entry if you would rather the puzzle be the only way through.
* Nothing here defends against malware on the machine, or someone who knows
  your vault password.

## Not losing it

A saved code should not be able to disappear. So:

* **Two copies, two stores.** Every save writes to `localStorage` *and* mirrors
  to IndexedDB with a revision number. If one is cleared, the next load
  restores it from the other and says so.
* **Persistent storage** is requested from the browser when the vault is
  created, so it is not first in line for eviction.
* **A locked entry cannot be deleted.** No button, no shortcut. Open it — wait
  the date out, or solve the puzzle — and then the delete appears, and it asks
  you to type DELETE. Deleting is for codes you can already see.
* **A restore that would replace a newer vault says so**, with the date of what
  it is about to overwrite, before it does anything.
* **It nags** whenever there are changes you have not backed up. Housekeeping
  saves do not trip it; real edits do.
* The vault auto‑locks after five quiet minutes — thirty, mid‑walkthrough, so
  it never locks while you are at the keypad.

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
| `app.js` | crypto, vault, storage mirroring, puzzles, dictation, UI |
| `restore.html` | the standalone offline unlocker template |

No dependencies. Needs `crypto.subtle`, which browsers only expose on
`https://`, `localhost`, or `file://`.
