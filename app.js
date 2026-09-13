/* Keepsafe — a screen time code locker that runs entirely in your browser.
   Storage: one encrypted blob in localStorage. No network calls, ever. */

(() => {
'use strict';

const STORE   = 'keepsafe.vault.v1';
const KDF_IT  = 310000;   // vault password
const PZ_IT   = 600000;   // puzzle answer
const IDLE_MS = 5 * 60 * 1000;

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

/* ── state ─────────────────────────────────────────────────── */

const state = { key: null, vault: null, payload: null, view: null, entryId: null };
let ticker = null, idleTimer = null, lastPersist = 0;

/* Clock guard: winding the device clock back must not open anything, so the
   vault remembers the furthest point in time it has ever seen. */
const now = () => Math.max(Date.now(), state.payload ? (state.payload.seen || 0) : 0);
const clockSuspect = () => !!state.payload && Date.now() < (state.payload.seen || 0) - 60000;

function loadVault() {
  try { return JSON.parse(localStorage.getItem(STORE) || 'null'); }
  catch { return null; }
}

async function persist() {
  state.payload.seen = now();
  state.vault.data = await seal(state.key, JSON.stringify(state.payload));
  localStorage.setItem(STORE, JSON.stringify(state.vault));
  lastPersist = Date.now();
}

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
  const answer = (body.match(/\d+/g) || []).length;
  return { body, answer };
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
  toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
}

function show(view) {
  state.view = view;
  for (const id of ['view-setup', 'view-unlock', 'view-app']) $('#' + id).hidden = (id !== view);
}

function panel(name) {
  for (const id of ['list', 'new', 'entry', 'backup']) $('#panel-' + id).hidden = (id !== name);
}

/* ── list ──────────────────────────────────────────────────── */

function statusOf(e) {
  if (e.opened) return { label: 'Open', open: true };
  const timeLeft = e.unlockAt ? e.unlockAt - now() : 0;
  if (timeLeft > 0) return { label: 'Locked', open: false, until: e.unlockAt };
  if (e.puzzle) return { label: 'Puzzle', open: false };
  return { label: 'Ready', open: true };
}

function renderList() {
  panel('list');
  const list = $('#entry-list');
  const entries = state.payload.entries;
  $('#empty').hidden = entries.length > 0;

  list.innerHTML = entries.map(e => {
    const st = statusOf(e);
    const bits = [];
    if (e.unlockAt) {
      bits.push(e.unlockAt > now()
        ? `opens ${stamp(e.unlockAt)} · ${countdown(e.unlockAt - now())}`
        : `date passed ${stamp(e.unlockAt)}`);
    }
    if (e.puzzle && !e.opened) bits.push(`${e.puzzle.size} puzzle`);
    if (e.opened) bits.push(`opened ${stamp(e.openedAt)}`);
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

  const body = $('#entry-body');
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
    parts.push(`<p class="lede">Count the numbers in the block. A run of digits — <span style="font-family:var(--mono)">4</span>, <span style="font-family:var(--mono)">17</span>, <span style="font-family:var(--mono)">903</span> — counts as one number.</p>
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
    e.opened = true; e.openedAt = now(); persist();
  }

  parts.push(`<div class="block"><h3>Details</h3><dl class="facts">
    <div><dt>Locked</dt><dd>${esc(stamp(e.createdAt))}</dd></div>
    ${e.unlockAt ? `<div><dt>Opens</dt><dd>${esc(stamp(e.unlockAt))}</dd></div>` : ''}
    <div><dt>Puzzle</dt><dd>${e.puzzle ? esc(e.puzzle.size) + (e.opened ? ' · solved' : '') : 'none'}</dd></div>
    </dl>
    <div class="row" style="margin-top:20px">
      <button class="btn btn-danger" type="button" data-delete>Delete for good</button>
    </div>
    <p class="hint">Deleting destroys the code. It does not show it to you.</p>
  </div>`);

  body.innerHTML = parts.join('');
}

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
    await persist();
    renderEntry(e.id);
    toast('Not the right count.');
    return;
  }

  e.secret = secret;
  e.opened = true;
  e.openedAt = now();
  delete e.puzzle.body;
  await persist();
  renderEntry(e.id);
}

async function newEntry(ev) {
  ev.preventDefault();
  const err = $('#new-error');
  err.hidden = true;

  const label = $('#new-label').value.trim();
  const secret = $('#new-secret').value.trim();
  const useTime = $('#cond-time').checked;
  const usePuzzle = $('#cond-puzzle').checked;

  const fail = m => { err.textContent = m; err.hidden = false; };
  if (!label || !secret) return fail('A name and a code, please.');
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
    secret: null, puzzle: null
  };

  if (usePuzzle) {
    const size = $('#puzzle-presets .is-on').dataset.size;
    const { body, answer } = makePuzzle(size);
    const salt = rand(16);
    const key = await deriveKey(String(answer), salt, PZ_IT);
    const blob = await seal(key, secret);
    entry.puzzle = { size, body, salt: b64(salt), iv: blob.iv, ct: blob.ct, attempts: 0, nextTryAt: 0 };
  } else {
    entry.secret = secret;
  }

  state.payload.entries.unshift(entry);
  await persist();
  $('#form-new').reset();
  renderList();
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

async function downloadJson() {
  await persist();
  download(`keepsafe-vault-${fileStamp()}.json`,
    JSON.stringify(state.vault, null, 2), 'application/json');
  toast('Vault file saved.');
}

async function downloadHtml() {
  await persist();
  let src;
  try {
    const res = await fetch('restore.html', { cache: 'no-store' });
    if (!res.ok) throw new Error(res.status);
    src = await res.text();
  } catch {
    toast('Could not build the offline file — saving the vault file instead.');
    return downloadJson();
  }
  const json = JSON.stringify(state.vault).replace(/</g, '\\u003c');
  const marker = 'var EMBEDDED = null; // __KEEPSAFE_EMBED__';
  if (!src.includes(marker)) { toast('Offline template is out of date.'); return downloadJson(); }
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
  if (loadVault() && !confirm('Replace the vault on this device with the backup? Anything in it that is not in the backup is lost.')) return;
  localStorage.setItem(STORE, JSON.stringify(data));
  boot();
  toast('Backup restored. Unlock it with the password it was saved under.');
}

/* ── session ───────────────────────────────────────────────── */

function lock() {
  state.key = null; state.payload = null; state.entryId = null;
  clearInterval(ticker); ticker = null;
  clearTimeout(idleTimer);
  $('#unlock-pw').value = '';
  show('view-unlock');
  setTimeout(() => $('#unlock-pw').focus(), 30);
}

function nudgeIdle() {
  if (!state.key) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { lock(); toast('Locked after five quiet minutes.'); }, IDLE_MS);
}

function tick() {
  if (!state.payload) return;
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
  if (Date.now() - lastPersist > 60000) persist();
}

async function enter(password, isNew) {
  const vault = loadVault();
  const salt = unb64(vault.kdf.salt);
  const key = await deriveKey(password, salt, vault.kdf.iterations);
  const payload = JSON.parse(await open_(key, vault.data));   // throws on a wrong password
  state.key = key; state.vault = vault; state.payload = payload;
  if (!Array.isArray(payload.entries)) payload.entries = [];
  await persist();
  show('view-app');
  renderList();
  clearInterval(ticker);
  ticker = setInterval(tick, 1000);
  nudgeIdle();
  if (isNew) toast('Vault created. Download a backup once you have locked something.');
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
  const salt = rand(16);
  const key = await deriveKey(pw, salt, KDF_IT);
  const payload = { entries: [], seen: Date.now() };
  const vault = {
    v: 1,
    kdf: { salt: b64(salt), iterations: KDF_IT, hash: 'SHA-256' },
    data: await seal(key, JSON.stringify(payload))
  };
  localStorage.setItem(STORE, JSON.stringify(vault));
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

function boot() {
  show(loadVault() ? 'view-unlock' : 'view-setup');
  if (loadVault()) setTimeout(() => $('#unlock-pw').focus(), 30);
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

$('#entry-list').addEventListener('click', ev => {
  const btn = ev.target.closest('.entry');
  if (btn) renderEntry(btn.dataset.id);
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

  const ext = t.closest('[data-extend]');
  if (ext) {
    const add = Number(ext.dataset.extend) * 60000;
    e.unlockAt = Math.max(e.unlockAt || now(), now()) + add;
    await persist();
    renderEntry(e.id);
    toast(`Pushed back by ${coarse(add)}.`);
  }

  if (t.closest('[data-relock]')) {
    const mins = prompt('Lock it away again for how many minutes?', '1440');
    const n = Number(mins);
    if (!n || n <= 0) return;
    e.unlockAt = now() + n * 60000;
    e.opened = false; e.openedAt = null;
    await persist();
    renderEntry(e.id);
  }

  if (t.closest('[data-delete]')) {
    if (!confirm(`Delete “${e.label}”? The code inside is destroyed, not revealed.`)) return;
    state.payload.entries = state.payload.entries.filter(x => x.id !== e.id);
    await persist();
    renderList();
    toast('Deleted.');
  }
});

['click', 'keydown', 'pointerdown'].forEach(ev =>
  document.addEventListener(ev, nudgeIdle, { passive: true }));
document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });

boot();
})();
