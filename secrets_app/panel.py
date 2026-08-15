"""The Settings panel — one self-contained HTML page, no build step.

Why an iframe and not a declarative window: the workspace's declarative widget
vocabulary is ``markdown``/``list``/``button``/``form``/``collapsible``/
``auth_status`` (see aw-workspace-ui's AppWindow.jsx). ``list`` renders static
strings from the manifest and there is no table or data-bound repeater, so a
row-per-secret view with its own controls cannot be expressed there at all.
``iframe`` onto an app route is the supported escape hatch, and the one the
workspace's own notes point at for exactly this shape of UI.

Two constraints this page is written around, both from the host:

* the iframe is sandboxed ``allow-scripts allow-forms allow-same-origin`` —
  **no** ``allow-modals``. ``prompt()``/``alert()``/``confirm()`` silently do
  nothing, so every input and every confirmation here is inline DOM. The reason
  box is not a nicety; a ``prompt()`` would have been a dead button.
* it loads from the API host, so relative ``/api/apps/secrets/...`` fetches are
  same-origin and the apex ``aw_id_jwt`` cookie rides along. No token handling
  in this file, and none should be added — a page that carries a credential in
  its markup is a page that leaks one.

Values are shown once, on request, and never rendered into the list. The list
is names and metadata, the same asymmetry the tools keep.
"""
from __future__ import annotations

PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secrets</title>
<style>
  :root {
    --bg: #0f1115; --panel: #171a21; --border: #262b36; --text: #e6e8ee;
    --muted: #939aab; --accent: #4f8cff; --warn: #f0a020; --danger: #e5484d;
    --ok: #3fb950;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 16px; background: var(--bg); color: var(--text);
    font: 13px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  h2 { font-size: 14px; margin: 0 0 2px; }
  .sub { color: var(--muted); font-size: 12px; margin-bottom: 14px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; margin-bottom: 12px;
  }
  .row {
    display: flex; align-items: center; gap: 10px; padding: 9px 0;
    border-bottom: 1px solid var(--border);
  }
  .row:last-child { border-bottom: 0; }
  .name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; }
  .desc { color: var(--muted); font-size: 11.5px; }
  .grow { flex: 1; min-width: 0; }
  button {
    background: #222735; color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 5px 10px; font-size: 12px; cursor: pointer;
  }
  button:hover { background: #2b3243; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button.danger { color: var(--danger); }
  button:disabled { opacity: .5; cursor: default; }
  input[type=text], input[type=password] {
    background: #10131a; color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 8px; font-size: 12px; width: 100%;
  }
  label.toggle { display: flex; align-items: center; gap: 6px; font-size: 11.5px;
                 color: var(--muted); cursor: pointer; white-space: nowrap; }
  .pill { font-size: 10.5px; padding: 1px 6px; border-radius: 999px;
          border: 1px solid var(--warn); color: var(--warn); white-space: nowrap; }
  .ask { padding: 8px 0 10px; display: none; gap: 8px; align-items: center; }
  .ask.open { display: flex; }
  /* Always visible, unlike .ask, which stays hidden until Reveal is pressed.
     Reusing .ask here made the allowlist editor invisible — the API had a
     setting the page silently never offered. */
  .allow { padding: 4px 0 10px; display: flex; gap: 8px; align-items: center; }
  .out { font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all;
         background: #10131a; border: 1px solid var(--border); border-radius: 6px;
         padding: 8px; margin: 2px 0 10px; display: none; }
  .out.open { display: block; }
  .status { font-size: 11.5px; color: var(--muted); }
  .status.err { color: var(--danger); }
  .status.ok { color: var(--ok); }
  .addgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px; }
  .banner { border: 1px solid var(--warn); color: var(--warn); border-radius: 6px;
            padding: 8px 10px; font-size: 11.5px; margin-bottom: 12px; }
</style>
</head>
<body>
<h2>Secrets</h2>
<div class="sub">Shared, human-gated secrets. Values live in aw-vault; reading one
asks for approval on Telegram unless its gate is off.</div>

<div id="banner" class="banner" style="display:none"></div>

<div class="card">
  <div id="list"><div class="status">Loading…</div></div>
</div>

<div class="card">
  <div style="font-size:12.5px;margin-bottom:8px">Add or replace a secret</div>
  <div class="addgrid">
    <input type="text" id="new-name" placeholder="name (e.g. resend_api_key)">
    <input type="text" id="new-desc" placeholder="description (optional)">
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <input type="password" id="new-value" placeholder="value" class="grow">
    <button class="primary" id="add-btn">Save</button>
  </div>
  <div class="status" id="add-status" style="margin-top:6px"></div>
</div>

<script>
const API = '/api/apps/secrets';
const POLL_MS = 2000, POLL_CEILING_MS = 300000;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

async function api(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: body ? {'Content-Type': 'application/json'} : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || (method + ' ' + path + ' -> ' + res.status));
  return data;
}

function banner(msg) {
  const b = document.getElementById('banner');
  b.textContent = msg;
  b.style.display = msg ? 'block' : 'none';
}

async function load() {
  const list = document.getElementById('list');
  try {
    const data = await api('GET', '/secrets');
    banner('');
    list.textContent = '';
    if (!data.secrets || !data.secrets.length) {
      list.appendChild(el('div', 'status', 'No secrets stored yet.'));
      return;
    }
    data.secrets.forEach(s => list.appendChild(secretRow(s)));
  } catch (e) {
    list.textContent = '';
    list.appendChild(el('div', 'status err', String(e.message || e)));
  }
}

function secretRow(s) {
  const wrap = el('div');
  const row = el('div', 'row');

  const info = el('div', 'grow');
  info.appendChild(el('div', 'name', s.name));
  if (s.description) info.appendChild(el('div', 'desc', s.description));
  row.appendChild(info);

  if (s.auto_approve) row.appendChild(el('span', 'pill', 'no approval'));
  else if (s.auto_approve_for) row.appendChild(
    el('span', 'pill', 'open to ' + s.auto_approve_for.split(',').length + ' caller(s)'));

  // The gate toggle. Checked = instant release, i.e. NO human asked.
  const lab = el('label', 'toggle');
  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.checked = !!s.auto_approve;
  lab.appendChild(cb);
  lab.appendChild(el('span', null, 'instant'));
  row.appendChild(lab);

  const reveal = el('button', null, 'Reveal');
  row.appendChild(reveal);

  const del = el('button', 'danger', 'Delete');
  row.appendChild(del);
  wrap.appendChild(row);

  // Inline reason box — no prompt() available in this sandbox.
  const ask = el('div', 'ask');
  const reason = document.createElement('input');
  reason.type = 'text';
  reason.placeholder = 'Why do you need it? (the approver reads this)';
  reason.className = 'grow';
  const go = el('button', 'primary', 'Request');
  ask.appendChild(reason); ask.appendChild(go);
  wrap.appendChild(ask);

  // Who may read this one WITHOUT a prompt. A second, narrower answer to the
  // question the "instant" toggle answers bluntly: that opens the secret to
  // everything in the workspace, this opens it to the callers you name — the
  // 3am scheduled task, and nothing else. Shown next to the toggle because a
  // reader comparing the two is exactly the decision being made.
  const allow = el('div', 'allow');
  allow.appendChild(el('span', 'desc', 'No approval for:'));
  const who = document.createElement('input');
  who.type = 'text';
  who.className = 'grow';
  who.value = s.auto_approve_for || '';
  who.placeholder = 'agent:nightly-backup, agent:another — empty means nobody';
  const saveWho = el('button', null, 'Save');
  allow.appendChild(who); allow.appendChild(saveWho);
  wrap.appendChild(allow);

  const out = el('div', 'out');
  wrap.appendChild(out);
  const status = el('div', 'status');
  status.style.paddingBottom = '6px';
  wrap.appendChild(status);

  saveWho.addEventListener('click', async () => {
    saveWho.disabled = true;
    try {
      // auto_approve is sent unchanged: this button edits WHO, not whether.
      await api('PUT', '/policies/' + encodeURIComponent(s.name),
                {auto_approve: !!s.auto_approve, auto_approve_for: who.value,
                 updated_by: 'settings-panel'});
      status.className = 'status';
      status.textContent = who.value.trim()
        ? 'Saved — those callers read it without asking anyone.'
        : 'Saved — nobody skips the approval for this one.';
      await load();
    } catch (e) {
      status.className = 'status err';
      status.textContent = String(e.message || e);
    } finally {
      saveWho.disabled = false;
    }
  });

  cb.addEventListener('change', async () => {
    cb.disabled = true;
    try {
      await api('PUT', '/policies/' + encodeURIComponent(s.name),
                {auto_approve: cb.checked, updated_by: 'settings-panel'});
      await load();
    } catch (e) {
      cb.checked = !cb.checked;
      status.className = 'status err';
      status.textContent = String(e.message || e);
    } finally {
      cb.disabled = false;
    }
  });

  del.addEventListener('click', () => {
    // Two-step instead of confirm() — confirm() is inert in this sandbox, so a
    // one-click delete would have had no confirmation at all.
    if (del.dataset.armed !== '1') {
      del.dataset.armed = '1';
      del.textContent = 'Really delete?';
      setTimeout(() => { del.dataset.armed = '0'; del.textContent = 'Delete'; }, 4000);
      return;
    }
    del.disabled = true;
    api('DELETE', '/secrets/' + encodeURIComponent(s.name))
      .then(load)
      .catch(e => { status.className = 'status err'; status.textContent = String(e.message || e); del.disabled = false; });
  });

  reveal.addEventListener('click', () => {
    ask.classList.toggle('open');
    if (ask.classList.contains('open')) reason.focus();
  });
  reason.addEventListener('keydown', ev => { if (ev.key === 'Enter') go.click(); });
  go.addEventListener('click', () => request(s, reason, go, out, status));

  return wrap;
}

async function request(s, reasonInput, go, out, status) {
  const reason = (reasonInput.value || '').trim();
  if (!reason) {
    status.className = 'status err';
    status.textContent = 'A reason is required — it is the only thing the approver sees besides the name.';
    return;
  }
  go.disabled = true;
  out.classList.remove('open');
  status.className = 'status';
  status.textContent = 'Requesting…';
  try {
    const r = await api('POST', '/secrets/' + encodeURIComponent(s.name) + '/read',
                        {reason: reason, max_wait_s: 0});
    if (r.status === 'approved' && r.value !== undefined && r.value !== null) {
      show(out, status, r.value, s.auto_approve ? 'Released with no approval (gate off).'
                                                : 'Approved.');
      go.disabled = false;
      return;
    }
    status.textContent = 'Waiting for approval on Telegram… (request ' + r.request_id + ')';
    poll(r.request_id, out, status, go, Date.now() + POLL_CEILING_MS);
  } catch (e) {
    status.className = 'status err';
    status.textContent = String(e.message || e);
    go.disabled = false;
  }
}

function poll(id, out, status, go, deadline) {
  setTimeout(async () => {
    if (Date.now() > deadline) {
      status.className = 'status err';
      status.textContent = 'No answer in time. The request may still be live — ask again if needed.';
      go.disabled = false;
      return;
    }
    try {
      const r = await api('GET', '/requests/' + encodeURIComponent(id));
      if (r.status === 'approved' && r.value) {
        show(out, status, r.value, 'Approved.');
        go.disabled = false;
        return;
      }
      poll(id, out, status, go, deadline);
    } catch (e) {
      // 403 is the approval being denied/expired — a real answer, not a failure.
      status.className = 'status err';
      status.textContent = String(e.message || e);
      go.disabled = false;
    }
  }, POLL_MS);
}

function show(out, status, value, note) {
  out.textContent = value;
  out.classList.add('open');
  status.className = 'status ok';
  status.textContent = note + ' Shown once — the value is not kept on this page.';
}

document.getElementById('add-btn').addEventListener('click', async () => {
  const name = document.getElementById('new-name').value.trim();
  const value = document.getElementById('new-value').value;
  const desc = document.getElementById('new-desc').value.trim();
  const st = document.getElementById('add-status');
  st.className = 'status';
  st.textContent = 'Saving…';
  try {
    const r = await api('POST', '/secrets', {name: name, value: value, description: desc});
    st.className = 'status ok';
    st.textContent = name + ' ' + (r.action || 'written') + '.';
    document.getElementById('new-name').value = '';
    document.getElementById('new-value').value = '';
    document.getElementById('new-desc').value = '';
    load();
  } catch (e) {
    st.className = 'status err';
    st.textContent = String(e.message || e);
  }
});

load();
</script>
</body>
</html>
"""
