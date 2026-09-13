/* Keepsafe — a screen time code locker that runs entirely in your browser.
   Storage: one encrypted blob, kept in localStorage and mirrored to IndexedDB.
   No network calls, ever. */

(() => {
'use strict';

const STORE   = 'keepsafe.vault.v1';
const IDB_DB  = 'keepsafe', IDB_STORE = 'vault', IDB_KEY = 'v1';
const KDF_IT  = 310000;   // vault password
const PZ_IT   = 600000;   // puzzle answer
const IDLE_MS = 5 * 60 * 1000;
const GUIDE_IDLE_MS = 30 * 60 * 1000;   // don't lock mid-walkthrough

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

/* ── bytes ─────────────────────────────────────────────────── */

const te = new TextEncoder(), td = new TextDecoder();
const rand = n => crypto.getRandomValues(new Uint8Array(n));

function b64(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ── crypto ────────────────────────────────────────────────── */

async function deriveKey(secret, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', te.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function seal(key, text) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text));
  return { iv: b64(iv), ct: b64(ct) };
}

async function open_(key, blob) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
  return td.decode(pt);
}

/* ── storage ───────────────────────────────────────────────── */
/* Two copies in two different stores. A code that has been saved should
   survive anything short of the user clearing the whole site. */

function openIdb() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(IDB_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function idbPut(vault) {
  try {
    const db = await openIdb();
    await new Promise((res, rej) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(vault, IDB_KEY);
      tx.oncomplete = res; tx.onerror = () => rej(tx.error);
    });
    db.close();
  } catch { /* private mode, quota, no IndexedDB — localStorage still has it */ }
}

async function idbGet() {
  try {
    const db = await openIdb();
    const v = await new Promise((res, rej) => {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const q = tx.objectStore(IDB_STORE).get(IDB_KEY);
      q.onsuccess = () => res(q.result || null);
      q.onerror = () => rej(q.error);
    });
    db.close();
    return v;
  } catch { return null; }
}

function loadVault() {
  try { return JSON.parse(localStorage.getItem(STORE) || 'null'); }
  catch { return null; }
}

function writeVault(vault) {
  try { localStorage.setItem(STORE, JSON.stringify(vault)); }
  catch { toast('This browser refused to save. Download a backup now.'); }
  idbPut(vault);
}

const revOf = v => (v && v.rev) || 0;

/* ── state ─────────────────────────────────────────────────── */

const state = { key: null, vault: null, payload: null, view: null, entryId: null };
let ticker = null, idleTimer = null, lastPersist = 0;

/* Clock guard: winding the device clock back must not open anything, so the
   vault remembers the furthest point in time it has ever seen. */
const now = () => Math.max(Date.now(), state.payload ? (state.payload.seen || 0) : 0);
const clockSuspect = () => !!state.payload && Date.now() < (state.payload.seen || 0) - 60000;

/* `changed` marks a real edit. Housekeeping saves (clock keeping, unlocking
   the session) still bump the storage revision, but must not make a good
   backup look stale. */
async function persist(changed) {
  state.payload.seen = now();
  if (changed) state.payload.dataRev = (state.payload.dataRev || 0) + 1;
  state.vault.rev = revOf(state.vault) + 1;
  state.vault.savedAt = Date.now();
  state.vault.data = await seal(state.key, JSON.stringify(state.payload));
  writeVault(state.vault);
  lastPersist = Date.now();
}

const backupStale = () => (state.payload.dataRev || 0) > (state.payload.backedUpRev || 0);

/* ── puzzle ────────────────────────────────────────────────── */

const SIZES = {
  light:  { lines: 8,  cols: 30, numbers: 22 },
  medium: { lines: 16, cols: 34, numbers: 48 },
  heavy:  { lines: 28, cols: 38, numbers: 95 }
};

/* A block of letters with whole numbers scattered through it. The answer is
   how many numbers there are (a run of digits counts once). */
function makePuzzle(size) {
  const spec = SIZES[size] || SIZES.medium;
  const letters = 'abcdefghijkmnopqrstuvwxyz';
  const cells = [];
  for (let i = 0; i < spec.lines * spec.cols; i++) {
    cells.push(letters[Math.floor(Math.random() * letters.length)]);
  }

  let placed = 0, guard = 0;
  while (placed < spec.numbers && guard++ < spec.numbers * 200) {
    const len = 1 + Math.floor(Math.random() * 3);
    const line = Math.floor(Math.random() * spec.lines);
    const col = Math.floor(Math.random() * (spec.cols - len));
    const start = line * spec.cols + col;
    let clear = true;
    for (let i = -1; i <= len; i++) {                 // keep a letter either side
      const c = cells[start + i];
      if (col + i >= 0 && col + i < spec.cols && c !== undefined && /[0-9]/.test(c)) clear = false;
    }
    if (!clear) continue;
    for (let i = 0; i < len; i++) cells[start + i] = String(Math.floor(Math.random() * 10));
    placed++;
  }

  const rows = [];
  for (let l = 0; l < spec.lines; l++) rows.push(cells.slice(l * spec.cols, (l + 1) * spec.cols).join(''));
  const body = rows.join('\n');
  return { body, answer: (body.match(/\d+/g) || []).length };
}

/* ── dictation ─────────────────────────────────────────────── */
/* One digit at a time, with wrong digits mixed in and deleted again, so that
   what you remember afterwards is not the code. Two rules keep it usable on a
   phone: the field never reaches full length until the very last step (iOS
   submits a screen time passcode the instant the fourth digit lands), and a
   "delete" is as likely to remove a right digit as a wrong one, so you cannot
   read the sequence backwards from where you were told to delete. */

function makeCode(len) {
  const weak = c => /^(\d)\1*$/.test(c) ||
    '0123456789012'.includes(c) || '9876543210987'.includes(c);
  let out;
  do {
    out = '';
    while (out.length < len) {
      for (const b of rand(len * 2)) {
        if (b < 250 && out.length < len) out += String(b % 10);
      }
    }
  } while (weak(out));
  return out;
}

function replay(steps) {
  const buf = [];
  for (const s of steps) s.act === 'del' ? buf.pop() : buf.push(s.ch);
  return buf.join('');
}

function overfills(steps, len) {
  let n = 0;
  for (let i = 0; i < steps.length; i++) {
    n += steps[i].act === 'del' ? -1 : 1;
    if (n >= len && i < steps.length - 1) return true;   // would submit early
  }
  return false;
}

function draftDictation(code) {
  const digits = [...code], L = digits.length;
  const numeric = /^\d+$/.test(code);
  const wrongFor = right => {
    const pool = numeric ? '0123456789' : 'abcdefghijklmnopqrstuvwxyz0123456789';
    let c;
    do { c = pool[Math.floor(Math.random() * pool.length)]; } while (c === right);
    return c;
  };

  const steps = [], buf = [];
  let noise = L + 1, guard = 0;
  const onTrack = () => buf.every((c, i) => c === digits[i]);

  while (guard++ < 400) {
    if (!onTrack()) { steps.push({ act: 'del' }); buf.pop(); continue; }
    if (buf.length === L - 1 && noise <= 0) {
      steps.push({ act: 'type', ch: digits[L - 1] });
      buf.push(digits[L - 1]);
      break;
    }
    const room = buf.length < L - 1;                       // safe to add a decoy
    const beNoisy = noise > 0 && (!room || Math.random() < 0.5);
    if (beNoisy && room && (buf.length === 0 || Math.random() < 0.6)) {
      const w = wrongFor(digits[buf.length]);
      steps.push({ act: 'type', ch: w }); buf.push(w); noise--;
    } else if (beNoisy && buf.length > 0) {
      steps.push({ act: 'del' }); buf.pop(); noise--;      // deletes a *right* digit
    } else {
      steps.push({ act: 'type', ch: digits[buf.length] }); buf.push(digits[buf.length]);
    }
  }
  return steps;
}

function dictation(code) {
  if ([...code].length < 2) return [...code].map(ch => ({ act: 'type', ch }));
  for (let i = 0; i < 25; i++) {
    const steps = draftDictation(code);
    if (replay(steps) === code && !overfills(steps, [...code].length)) return steps;
  }
  return [...code].map(ch => ({ act: 'type', ch }));       // plain, but correct
}

/* ── time ──────────────────────────────────────────────────── */

function countdown(ms) {
  if (ms <= 0) return '00:00:00';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = String(Math.floor(s % 86400 / 3600)).padStart(2, '0');
  const m = String(Math.floor(s % 3600 / 60)).padStart(2, '0');
  const sec = String(s % 60).padStart(2, '0');
  return (d ? `${d}d ` : '') + `${h}:${m}:${sec}`;
}

function coarse(ms) {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s} seconds`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m} minutes`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hours`;
  return `${Math.round(h / 24)} days`;
}

const stamp = ms => new Date(ms).toLocaleString([], {
  year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
});

function localInput(ms) {
  const d = new Date(ms - new Date().getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 16);
}

/* ── chrome ────────────────────────────────────────────────── */

const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let toastTimer = null;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

function show(view) {
  state.view = view;
  for (const id of ['view-setup', 'view-unlock', 'view-app']) $('#' + id).hidden = (id !== view);
}

function panel(name) {
  for (const id of ['list', 'new', 'entry', 'guide', 'backup']) $('#panel-' + id).hidden = (id !== name);
}

/* ── list ──────────────────────────────────────────────────── */

const codeFor = e => (e.opened ? e.secret : e.guide) || null;   // what the walkthrough may read

function statusOf(e) {
  if (e.opened) return { label: 'Open', open: true };
  if (e.unlockAt && e.unlockAt > now()) return { label: 'Locked', open: false };
  if (e.puzzle) return { label: 'Puzzle', open: false };
  return { label: 'Ready', open: true };
}

function renderList() {
  panel('list');
  const entries = state.payload.entries;
  $('#empty').hidden = entries.length > 0;

  const nag = $('#backup-nag');
  nag.hidden = !(entries.length && backupStale());
  if (!nag.hidden) {
    nag.innerHTML = `<span>${(state.payload.backedUpRev || 0) === 0
      ? 'Nothing here is backed up yet.'
      : 'There are changes since your last backup.'} A browser can lose its storage — keep a copy.</span>
      <button class="btn" type="button" data-nag>Back it up</button>`;
  }

  $('#entry-list').innerHTML = entries.map(e => {
    const st = statusOf(e);
    const bits = [];
    if (e.unlockAt) {
      bits.push(e.unlockAt > now()
        ? `opens ${stamp(e.unlockAt)} · ${countdown(e.unlockAt - now())}`
        : `date passed ${stamp(e.unlockAt)}`);
    }
    if (e.puzzle && !e.opened) bits.push(`${e.puzzle.size} puzzle`);
    if (e.opened) bits.push(`opened ${stamp(e.openedAt)}`);
    if (!e.dictated && e.madeUp) bits.push('never typed into a device');
    return `<li><button class="entry" type="button" data-id="${esc(e.id)}">
      <span>
        <span class="entry-name">${esc(e.label)}</span>
        <span class="entry-meta" data-clock="${e.unlockAt && !e.opened ? e.unlockAt : ''}">${esc(bits.join('  ·  '))}</span>
      </span>
      <span class="entry-state ${st.open ? 'open' : ''}">${st.label}</span>
    </button></li>`;
  }).join('');
}

/* ── one entry ─────────────────────────────────────────────── */

function renderEntry(id) {
  const e = state.payload.entries.find(x => x.id === id);
  if (!e) return renderList();
  state.entryId = id;
  panel('entry');
  $('#entry-title').textContent = e.label;

  const parts = [];
  const timeLeft = e.unlockAt ? e.unlockAt - now() : 0;

  if (e.opened) {
    parts.push(`<div class="reveal">${esc(e.secret)}</div>
      <div class="row">
        <button class="btn" type="button" data-copy>Copy</button>
        <button class="btn btn-danger" type="button" data-relock>Lock it again</button>
      </div>`);
  } else if (timeLeft > 0) {
    parts.push(`<p class="gauge" data-clock="${e.unlockAt}">${countdown(timeLeft)}</p>
      <p class="gauge-label">until ${esc(stamp(e.unlockAt))}</p>`);
    if (clockSuspect()) parts.push(`<p class="error">This device's clock is behind the last time Keepsafe saw. The countdown is running on the later of the two.</p>`);
    if (e.puzzle) parts.push(`<p class="hint">A ${e.puzzle.size} counting puzzle is waiting after the date passes.</p>`);
    parts.push(`<div class="block"><h3>Change your mind the hard way</h3>
      <div class="row">
        <button class="btn" type="button" data-extend="60">+1 hour</button>
        <button class="btn" type="button" data-extend="1440">+1 day</button>
        <button class="btn" type="button" data-extend="10080">+1 week</button>
      </div>
      <p class="hint">A lock can be made longer, never shorter.</p></div>`);
  } else if (e.puzzle) {
    const wait = (e.puzzle.nextTryAt || 0) - now();
    parts.push(`<p class="lede">Count the numbers in the block. A run of digits — <span class="tt">4</span>, <span class="tt">17</span>, <span class="tt">903</span> — counts as one number.</p>
      <pre class="grid">${esc(e.puzzle.body)}</pre>
      <form class="answer" id="form-answer">
        <input type="number" id="answer" inputmode="numeric" min="0" required placeholder="how many"${wait > 0 ? ' disabled' : ''}>
        <button class="btn btn-solid" type="submit"${wait > 0 ? ' disabled' : ''}>Unlock</button>
      </form>
      <p class="hint" id="answer-note" data-clock="${wait > 0 ? e.puzzle.nextTryAt : ''}">${wait > 0
        ? `Wrong answer. Try again in ${countdown(wait)}.`
        : (e.puzzle.attempts ? `${e.puzzle.attempts} wrong ${e.puzzle.attempts === 1 ? 'try' : 'tries'} so far.` : 'The count is the decryption key, so a wrong number simply will not open it.')}</p>`);
  } else {
    parts.push(`<div class="reveal">${esc(e.secret)}</div>
      <div class="row"><button class="btn" type="button" data-copy>Copy</button></div>`);
    e.opened = true; e.openedAt = now(); persist(true);
  }

  if (codeFor(e)) {
    parts.push(`<div class="block"><h3>Type it into a device</h3>
      <div class="row"><button class="btn btn-solid" type="button" data-guide>Dictate it to me</button></div>
      <p class="hint">One digit at a time, wrong digits mixed in, twice over for the confirmation screen${e.dictated ? ` · last done ${esc(stamp(e.dictated))}` : ''}.</p></div>`);
  } else if (!e.opened) {
    parts.push(`<div class="block"><h3>Type it into a device</h3>
      <p class="hint">Not available for this one: guided entry was turned off, so nothing but the puzzle answer can read the code.</p></div>`);
  }

  parts.push(`<div class="block"><h3>Details</h3><dl class="facts">
    <div><dt>Locked</dt><dd>${esc(stamp(e.createdAt))}</dd></div>
    ${e.unlockAt ? `<div><dt>Opens</dt><dd>${esc(stamp(e.unlockAt))}</dd></div>` : ''}
    <div><dt>Puzzle</dt><dd>${e.puzzle ? esc(e.puzzle.size) + (e.opened ? ' · solved' : '') : 'none'}</dd></div>
    <div><dt>Origin</dt><dd>${e.madeUp ? 'invented here, never shown' : 'typed in by you'}</dd></div>
    </dl>
    ${e.opened
      ? `<div class="row" style="margin-top:20px"><button class="btn btn-danger" type="button" data-delete>Delete for good</button></div>
         <p class="hint">You are looking at the code, so you can afford to throw it away. It will ask you to type DELETE.</p>`
      : `<p class="hint" style="margin-top:20px">A locked code cannot be deleted — that is the point of it. Open it first, then delete it if you still want to.</p>`}
  </div>`);

  $('#entry-body').innerHTML = parts.join('');
}

/* ── the walkthrough ───────────────────────────────────────── */

const guide = { code: null, entryId: null, pass: 1, passes: 2, steps: [], i: 0, stage: 'intro', fresh: false };

function startGuide(code, entryId, fresh) {
  guide.code = code; guide.entryId = entryId; guide.fresh = !!fresh;
  guide.pass = 1; guide.passes = 2; guide.i = 0; guide.stage = 'intro';
  guide.steps = dictation(code);
  renderGuide();
}

function guideActive() { return !$('#panel-guide').hidden; }

function renderGuide() {
  panel('guide');
  const body = $('#guide-body');
  const passLine = `Pass ${guide.pass} of ${guide.passes}`;

  if (guide.stage === 'intro') {
    $('#guide-title').textContent = guide.fresh ? 'Set it on the device' : 'Type it into a device';
    body.innerHTML = `
      <p class="lede">${guide.fresh
        ? 'The code is saved and locked. Now put it on the phone without learning it.'
        : 'You will type the code into the phone without seeing it whole.'}</p>
      <ol class="steps">
        <li>On the phone: <span class="tt">Settings → Screen Time → Lock Screen Time Settings</span> (or <span class="tt">Change Screen Time Passcode</span>), and stop at the keypad.</li>
        <li>Keepsafe gives you one digit at a time. Type it, press Next, forget it.</li>
        <li>Some digits are wrong on purpose — you will be told to delete. Deletes take away right digits too, so do not try to reason about which was which.</li>
        <li>iPhone asks for the passcode twice. The second pass looks nothing like the first.</li>
      </ol>
      <div class="row"><button class="btn btn-solid" type="button" data-go>I am at the keypad</button>
        <button class="btn btn-quiet" type="button" data-stop>Not now</button></div>`;
    return;
  }

  if (guide.stage === 'between') {
    $('#guide-title').textContent = 'Once more';
    body.innerHTML = `<p class="lede">The phone should be asking for it again to confirm. Get to that keypad — the digits will come in a different order this time.</p>
      <div class="row"><button class="btn btn-solid" type="button" data-go>Ready</button>
        <button class="btn btn-quiet" type="button" data-stop>Stop</button></div>`;
    return;
  }

  if (guide.stage === 'done') {
    $('#guide-title').textContent = 'Done';
    body.innerHTML = `<p class="lede">That is the code set. It is locked away here and you never saw it whole.</p>
      <p class="hint">If the phone rejected it, run it again — and remember iOS starts adding delays after a few wrong tries.</p>
      <div class="row">
        <button class="btn btn-solid" type="button" data-finish>Finished</button>
        <button class="btn" type="button" data-again>Run it again</button>
      </div>`;
    return;
  }

  const step = guide.steps[guide.i];
  const last = guide.i === guide.steps.length - 1;
  $('#guide-title').textContent = passLine;
  body.innerHTML = `
    <p class="dial${step.act === 'del' ? ' del' : ''}">${step.act === 'del' ? '⌫ delete' : esc(step.ch)}</p>
    <p class="dial-label">${step.act === 'del'
      ? 'Take the last digit back off'
      : 'Type this on the phone'}</p>
    <div class="row">
      <button class="btn btn-solid" type="button" data-next>${last ? 'Done with this pass' : 'Next'}</button>
      <span class="hint" style="margin:0">or press <span class="tt">space</span></span>
    </div>
    <div class="track"><span style="width:${Math.round((guide.i + 1) / guide.steps.length * 100)}%"></span></div>
    <div class="block"><h3>Something went wrong?</h3>
      <div class="row">
        <button class="btn" type="button" data-restart>Start this pass over</button>
        <button class="btn btn-quiet" type="button" data-stop>Stop</button>
      </div>
      <p class="hint">Starting over means clearing every digit on the phone first.</p></div>`;
}

async function guideNext() {
  if (guide.stage !== 'step') return;
  guide.i++;
  if (guide.i < guide.steps.length) return renderGuide();
  if (guide.pass < guide.passes) {
    guide.pass++; guide.i = 0;
    guide.steps = dictation(guide.code);      // a fresh scramble for the confirmation
    guide.stage = 'between';
    return renderGuide();
  }
  guide.stage = 'done';
  const e = state.payload.entries.find(x => x.id === guide.entryId);
  if (e) { e.dictated = now(); await persist(true); }
  renderGuide();
}

function guideStop() {
  const back = !guide.fresh && guide.entryId;
  guide.code = null; guide.steps = [];
  back ? renderEntry(back) : renderList();
}

$('#guide-body').addEventListener('click', ev => {
  const t = ev.target;
  if (t.closest('[data-go]'))      { guide.stage = 'step'; guide.i = 0; renderGuide(); }
  if (t.closest('[data-next]'))    guideNext();
  if (t.closest('[data-restart]')) { guide.steps = dictation(guide.code); guide.i = 0; renderGuide(); }
  if (t.closest('[data-again]'))   startGuide(guide.code, guide.entryId, false);
  if (t.closest('[data-finish]'))  guideStop();
  if (t.closest('[data-stop]'))    {
    if (guide.stage === 'step' && !confirm('Stop halfway? The phone may be left with a half-typed passcode.')) return;
    guideStop();
  }
});

$('#guide-quit').addEventListener('click', () => {
  if (guide.stage === 'step' && !confirm('Stop halfway? The phone may be left with a half-typed passcode.')) return;
  guideStop();
});

document.addEventListener('keydown', ev => {
  if (!guideActive() || guide.stage !== 'step') return;
  if (ev.key === ' ' || ev.key === 'Enter') { ev.preventDefault(); guideNext(); }
});

/* ── actions ───────────────────────────────────────────────── */

async function tryAnswer(ev) {
  ev.preventDefault();
  const e = state.payload.entries.find(x => x.id === state.entryId);
  const note = $('#answer-note');
  const guess = $('#answer').value.trim();
  if (!e || guess === '') return;

  note.textContent = 'Checking…';
  const key = await deriveKey(guess, unb64(e.puzzle.salt), PZ_IT);
  let secret = null;
  try { secret = await open_(key, e.puzzle); } catch { /* wrong count */ }

  if (secret === null) {
    e.puzzle.attempts = (e.puzzle.attempts || 0) + 1;
    const wait = Math.min(30000 * 2 ** (e.puzzle.attempts - 1), 30 * 60000);
    e.puzzle.nextTryAt = now() + wait;
    await persist(false);
    renderEntry(e.id);
    toast('Not the right count.');
    return;
  }

  e.secret = secret;
  e.opened = true;
  e.openedAt = now();
  delete e.puzzle.body;
  await persist(true);
  renderEntry(e.id);
}

function codeMode() { return $('#code-mode .is-on').dataset.mode; }

async function newEntry(ev) {
  ev.preventDefault();
  const err = $('#new-error');
  err.hidden = true;

  const label = $('#new-label').value.trim();
  const mode = codeMode();
  const secret = mode === 'mine' ? $('#new-secret').value.trim() : makeCode(Number(mode));
  const useTime = $('#cond-time').checked;
  const usePuzzle = $('#cond-puzzle').checked;
  const guided = $('#cond-guided').checked;

  const fail = m => { err.textContent = m; err.hidden = false; };
  if (!label) return fail('Give it a name.');
  if (!secret) return fail('Type the code, or have Keepsafe invent one.');
  if (!useTime && !usePuzzle) return fail('Pick at least one condition, otherwise nothing is locked.');

  let unlockAt = null;
  if (useTime) {
    const v = $('#new-until').value;
    if (!v) return fail('Set the date and time it should open.');
    unlockAt = new Date(v).getTime();
    if (!unlockAt || unlockAt <= now() + 30000) return fail('Choose a moment at least a minute from now.');
  }

  const entry = {
    id: b64(rand(9)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 10) + Date.now().toString(36),
    label, createdAt: now(), unlockAt, opened: false, openedAt: null,
    secret: null, guide: null, puzzle: null, madeUp: mode !== 'mine', dictated: null
  };

  if (usePuzzle) {
    const size = $('#puzzle-presets .is-on').dataset.size;
    const { body, answer } = makePuzzle(size);
    const salt = rand(16);
    const key = await deriveKey(String(answer), salt, PZ_IT);
    const blob = await seal(key, secret);
    entry.puzzle = { size, body, salt: b64(salt), iv: blob.iv, ct: blob.ct, attempts: 0, nextTryAt: 0 };
  } else {
    entry.secret = secret;                 // already behind the vault password
  }
  if (guided) entry.guide = secret;        // the copy the walkthrough may read

  state.payload.entries.unshift(entry);
  await persist(true);
  $('#form-new').reset();
  setCodeMode('mine');
  $('#cond-guided').checked = true;
  $('#puzzle-body').hidden = true;
  $('#time-body').hidden = false;
  startGuide(secret, entry.id, true);
  toast('Locked away.');
}

/* ── backup ────────────────────────────────────────────────── */

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

const fileStamp = () => new Date().toISOString().slice(0, 10);

/* Record the backup inside the very revision being exported, so the file and
   the vault agree that it happened. */
async function markBackedUp() {
  state.payload.backedUpRev = state.payload.dataRev || 0;
  await persist(false);
}

async function downloadJson() {
  await markBackedUp();
  download(`keepsafe-vault-${fileStamp()}.json`,
    JSON.stringify(state.vault, null, 2), 'application/json');
  toast('Vault file saved.');
}

async function downloadHtml() {
  let src;
  try {
    const res = await fetch('restore.html', { cache: 'no-store' });
    if (!res.ok) throw new Error(res.status);
    src = await res.text();
  } catch {
    toast('Could not build the offline file — saving the vault file instead.');
    return downloadJson();
  }
  const marker = 'var EMBEDDED = null; // __KEEPSAFE_EMBED__';
  if (!src.includes(marker)) { toast('Offline template is out of date.'); return downloadJson(); }
  await markBackedUp();
  const json = JSON.stringify(state.vault).replace(/</g, '\\u003c');
  download(`keepsafe-${fileStamp()}.html`, src.replace(marker, 'var EMBEDDED = ' + json + ';'), 'text/html');
  toast('Offline unlocker saved.');
}

function restore() { $('#restore-file').value = ''; $('#restore-file').click(); }

async function readRestore(ev) {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  let data;
  try {
    data = JSON.parse(await file.text());
    if (!data || data.v !== 1 || !data.kdf || !data.data) throw new Error('shape');
  } catch {
    toast('That is not a Keepsafe vault file.');
    return;
  }
  const here = loadVault() || await idbGet();
  if (here) {
    const older = revOf(data) < revOf(here);
    const when = here.savedAt ? ` (last saved ${stamp(here.savedAt)})` : '';
    if (!confirm(`Replace the vault in this browser${when} with the backup${
      older ? ' — which is OLDER than what is here' : ''}? Anything saved since the backup is lost.`)) return;
  }
  writeVault(data);
  await boot();
  toast('Backup restored. Unlock it with the password it was saved under.');
}

/* ── session ───────────────────────────────────────────────── */

function lock() {
  state.key = null; state.payload = null; state.entryId = null;
  guide.code = null; guide.steps = [];
  clearInterval(ticker); ticker = null;
  clearTimeout(idleTimer);
  $('#unlock-pw').value = '';
  show('view-unlock');
  setTimeout(() => $('#unlock-pw').focus(), 30);
}

function nudgeIdle() {
  if (!state.key) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { lock(); toast('Locked after five quiet minutes.'); },
    guideActive() ? GUIDE_IDLE_MS : IDLE_MS);
}

function tick() {
  if (!state.payload || guideActive()) return;
  const t = now();
  for (const el of $$('[data-clock]')) {
    const at = Number(el.dataset.clock);
    if (!at) continue;
    if (at <= t) {
      if (state.view === 'view-app') (state.entryId && !$('#panel-entry').hidden) ? renderEntry(state.entryId) : renderList();
      return;
    }
    const text = countdown(at - t);
    if (el.classList.contains('gauge')) el.textContent = text;
    else el.textContent = el.textContent.replace(/(?:\d+d )?\d\d:\d\d:\d\d/, text);
  }
  if (Date.now() - lastPersist > 60000) persist(false);
}

async function enter(password, isNew) {
  const vault = loadVault();
  const key = await deriveKey(password, unb64(vault.kdf.salt), vault.kdf.iterations);
  const payload = JSON.parse(await open_(key, vault.data));   // throws on a wrong password
  state.key = key; state.vault = vault; state.payload = payload;
  if (!Array.isArray(payload.entries)) payload.entries = [];
  if (payload.dataRev === undefined) payload.dataRev = payload.entries.length ? 1 : 0;
  await persist(false);
  show('view-app');
  renderList();
  clearInterval(ticker);
  ticker = setInterval(tick, 1000);
  nudgeIdle();
  if (isNew) toast('Vault created. Lock something away, then download a backup.');
}

async function createVault(ev) {
  ev.preventDefault();
  const err = $('#setup-error');
  err.hidden = true;
  const pw = $('#setup-pw').value, pw2 = $('#setup-pw2').value;
  if (pw.length < 8) { err.textContent = 'Eight characters or more.'; err.hidden = false; return; }
  if (pw !== pw2) { err.textContent = 'The two do not match.'; err.hidden = false; return; }

  const btn = $('#form-setup button[type=submit]');
  btn.disabled = true; btn.textContent = 'Deriving key…';
  try { navigator.storage && navigator.storage.persist && navigator.storage.persist(); } catch { /* fine */ }
  const salt = rand(16);
  const key = await deriveKey(pw, salt, KDF_IT);
  const payload = { entries: [], seen: Date.now(), dataRev: 0, backedUpRev: 0 };
  const vault = {
    v: 1, rev: 1, savedAt: Date.now(),
    kdf: { salt: b64(salt), iterations: KDF_IT, hash: 'SHA-256' },
    data: await seal(key, JSON.stringify(payload))
  };
  writeVault(vault);
  $('#form-setup').reset();
  btn.disabled = false; btn.textContent = 'Create vault';
  await enter(pw, true);
}

async function unlock(ev) {
  ev.preventDefault();
  const err = $('#unlock-error');
  err.hidden = true;
  const btn = $('#form-unlock button[type=submit]');
  btn.disabled = true; btn.textContent = 'Opening…';
  try {
    await enter($('#unlock-pw').value, false);
    $('#unlock-pw').value = '';
  } catch {
    err.textContent = 'Wrong password.';
    err.hidden = false;
  }
  btn.disabled = false; btn.textContent = 'Open';
}

/* ── wiring ────────────────────────────────────────────────── */

function setCodeMode(mode) {
  $$('#code-mode .chip').forEach(c => c.classList.toggle('is-on', c.dataset.mode === mode));
  const mine = mode === 'mine';
  $('#new-secret').hidden = !mine;
  $('#secret-hint').textContent = mine
    ? 'Write it down here once. After you save, it is gone from the screen.'
    : `Keepsafe invents ${mode} digits and never shows them to you. It will dictate them into your phone one at a time, twice, and that is the only time they leave the vault.`;
}

async function boot() {
  let local = loadVault();
  const mirror = await idbGet();
  if (mirror && revOf(mirror) > revOf(local)) {
    localStorage.setItem(STORE, JSON.stringify(mirror));
    local = mirror;
    toast('Recovered your vault from this browser’s second copy.');
  } else if (local && revOf(local) > revOf(mirror)) {
    idbPut(local);
  }
  show(local ? 'view-unlock' : 'view-setup');
  if (local) setTimeout(() => $('#unlock-pw').focus(), 30);
}

$('#form-setup').addEventListener('submit', createVault);
$('#form-unlock').addEventListener('submit', unlock);
$('#form-new').addEventListener('submit', newEntry);
$('#restore-file').addEventListener('change', readRestore);
$$('[data-restore]').forEach(b => b.addEventListener('click', restore));

$('#btn-lock').addEventListener('click', lock);
$('#btn-new').addEventListener('click', () => {
  panel('new');
  $('#new-until').value = localInput(now() + 24 * 3600 * 1000);
  $('#new-label').focus();
});
$('#btn-backup').addEventListener('click', () => panel('backup'));
$('#btn-dl-json').addEventListener('click', downloadJson);
$('#btn-dl-html').addEventListener('click', downloadHtml);
$$('[data-cancel]').forEach(b => b.addEventListener('click', renderList));

$('#cond-time').addEventListener('change', e => { $('#time-body').hidden = !e.target.checked; });
$('#cond-puzzle').addEventListener('change', e => { $('#puzzle-body').hidden = !e.target.checked; });

$('#code-mode').addEventListener('click', ev => {
  const chip = ev.target.closest('.chip');
  if (chip) setCodeMode(chip.dataset.mode);
});

$('#time-presets').addEventListener('click', ev => {
  const chip = ev.target.closest('.chip');
  if (!chip) return;
  $('#new-until').value = localInput(now() + Number(chip.dataset.mins) * 60000);
  $$('#time-presets .chip').forEach(c => c.classList.toggle('is-on', c === chip));
});

$('#puzzle-presets').addEventListener('click', ev => {
  const chip = ev.target.closest('.chip');
  if (!chip) return;
  $$('#puzzle-presets .chip').forEach(c => c.classList.toggle('is-on', c === chip));
});

$('#panel-list').addEventListener('click', ev => {
  const btn = ev.target.closest('.entry');
  if (btn) return renderEntry(btn.dataset.id);
  if (ev.target.closest('[data-nag]')) panel('backup');
});

$('#entry-body').addEventListener('submit', ev => {
  if (ev.target.id === 'form-answer') tryAnswer(ev);
});

$('#entry-body').addEventListener('click', async ev => {
  const e = state.payload && state.payload.entries.find(x => x.id === state.entryId);
  if (!e) return;
  const t = ev.target;

  if (t.closest('[data-copy]')) {
    try { await navigator.clipboard.writeText(e.secret); toast('Copied.'); }
    catch { toast('Copying is blocked here — read it off the screen.'); }
  }

  if (t.closest('[data-guide]')) startGuide(codeFor(e), e.id, false);

  const ext = t.closest('[data-extend]');
  if (ext) {
    const add = Number(ext.dataset.extend) * 60000;
    e.unlockAt = Math.max(e.unlockAt || now(), now()) + add;
    await persist(true);
    renderEntry(e.id);
    toast(`Pushed back by ${coarse(add)}.`);
  }

  if (t.closest('[data-relock]')) {
    const mins = Number(prompt('Lock it away again for how many minutes?', '1440'));
    if (!mins || mins <= 0) return;
    e.unlockAt = now() + mins * 60000;
    e.opened = false; e.openedAt = null;
    await persist(true);
    renderEntry(e.id);
  }

  if (t.closest('[data-delete]')) {
    if (!e.opened) return;
    if ((prompt(`Type DELETE to destroy “${e.label}” for good.`) || '').trim() !== 'DELETE') {
      toast('Left where it is.');
      return;
    }
    state.payload.entries = state.payload.entries.filter(x => x.id !== e.id);
    await persist(true);
    renderList();
    toast('Deleted.');
  }
});

['click', 'keydown', 'pointerdown'].forEach(ev =>
  document.addEventListener(ev, nudgeIdle, { passive: true }));
document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });

setCodeMode('mine');
boot();
})();
