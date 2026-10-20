(function () {
  'use strict';

  const MESSAGES = /* LOCALE */;
  let currentLocale = 'en';
  const viewPresence = new Map();
  const viewData = new Map();
  const simulatedApprovals = new Set();
  const pendingEvents = [];
  let bootstrapToken = '';
  let browserNonce = '';
  let humanConfig = '';

  function nonceText(bytes) {
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function browserNonceValue() {
    try {
      const stored = sessionStorage.getItem('laneboss.dashboard.nonce');
      if (stored && /^[A-Za-z0-9_-]{22}$/.test(stored)) return stored;
      if (!globalThis.crypto || !crypto.getRandomValues) throw new Error('Browser nonce generation is unavailable.');
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      const value = nonceText(bytes);
      sessionStorage.setItem('laneboss.dashboard.nonce', value);
      return value;
    } catch (error) {
      throw new Error('Browser-bound sign-in is unavailable in this context.');
    }
  }

  function readBootstrap() {
    let hash = '';
    if (typeof window !== 'undefined' && window.location) {
      hash = window.location.hash || '';
      if (hash && window.history && window.history.replaceState) {
        window.history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    }
    browserNonce = browserNonceValue();
    const nonceNode = byId('bootstrap-nonce');
    if (nonceNode) nonceNode.textContent = browserNonce;
    if (!hash) return;
    const params = new URLSearchParams(hash.slice(1));
    bootstrapToken = params.get('bootstrap') || '';
  }

  function canonical(value) {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (value && typeof value === 'object') {
      return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
    }
    return JSON.stringify(value);
  }

  async function digestRequest(config, method, params) {
    const body = canonical({config, method, params, protocol: 'laneboss.rpc.v2', schema: 2});
    if (!globalThis.crypto || !globalThis.crypto.subtle) throw new Error('Secure request hashing is unavailable.');
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
    return Array.from(new Uint8Array(bytes)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function requestID(prefix) {
    if (globalThis.crypto && crypto.randomUUID) return prefix + crypto.randomUUID();
    return prefix + Date.now().toString(16) + Math.random().toString(16).slice(2);
  }

  async function openSession() {
    if (!bootstrapToken) return;
    const headers = {'X-Laneboss-Dashboard-Bootstrap': bootstrapToken, 'X-Laneboss-Dashboard-Nonce': browserNonce};
    const preview = await fetch('/api/v2/bootstrap', {method: 'GET', credentials: 'same-origin', cache: 'no-store', headers});
    const info = await preview.json();
    if (!preview.ok || info.error || !info.config || !info.actor || !info.proof) {
      throw new Error(info.error && info.error.message ? info.error.message : 'Bootstrap preview refused.');
    }
    const principal = info.actor.kind + ':' + info.actor.id;
    if (typeof window.confirm !== 'function' || !window.confirm('Sign in as ' + principal + ' in configuration ' + info.config + '?')) {
      throw new Error('Sign-in was not confirmed.');
    }
    const params = {};
    const request = {
      protocol: 'laneboss.rpc.v2', schema: 2, config: info.config,
      request_id: requestID('req-'), idempotency_key: requestID('idem-'),
      method: 'human.session', params, proof: info.proof
    };
    request.request_sha256 = await digestRequest(info.config, request.method, params);
    const response = await fetch('/api/v2/rpc', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: Object.assign({'Content-Type': 'application/json'}, headers),
      body: JSON.stringify(request)
    });
    const result = await response.json();
    if (!response.ok || result.error) {
      throw new Error(result.error && result.error.message ? result.error.message : 'Human session refused.');
    }
    bootstrapToken = '';
    browserNonce = '';
  }

  function hasSimulatedPresence(value) {
    if (!value || typeof value !== 'object') return false;
    if (value.simulated_presence === true || (Boolean(value.approval_id) && simulatedApprovals.has(value.approval_id))) return true;
    return Object.values(value).some(hasSimulatedPresence);
  }

  function presenceText(simulated) {
    return 'presence=' + (simulated ? 'simulated' : 'not_proven') + '; human_approval=not_proven';
  }

  function recordPresence(name, value, headers) {
    viewData.set(name, { value: value, sessionSimulated: headers.get('X-Laneboss-Presence') === 'simulated' });
    (value.approvals || []).forEach(function (approval) {
      if (approval.simulated_presence && approval.id) simulatedApprovals.add(approval.id);
    });
    (value.applications || []).forEach(function (receipt) {
      if (receipt.simulated_presence && receipt.approval_id) simulatedApprovals.add(receipt.approval_id);
    });
    refreshPresence();
  }

  function refreshPresence() {
    viewData.forEach(function (entry, name) {
      viewPresence.set(name + '-content', entry.sessionSimulated || hasSimulatedPresence(entry.value));
    });
    const summary = byId('presence-summary');
    if (summary) summary.textContent = presenceText(Array.from(viewPresence.values()).some(Boolean));
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function tr(key) {
    const entry = MESSAGES[key];
    if (entry && entry[currentLocale]) {
      return entry[currentLocale];
    }
    return key;
  }

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    if (cls) {
      node.className = cls;
    }
    return node;
  }

  function renderTable(targetId, headers, rows, emptyMsg) {
    const container = byId(targetId);
    if (!container) return;
    headers = headers.concat(['Presence / Human approval']);
    rows = (rows || []).map(function (row) {
      return row.concat([presenceText(viewPresence.get(targetId) === true)]);
    });
    const tbl = el('table');
    const thead = el('thead');
    const hrow = el('tr');
    headers.forEach(function (h) {
      const th = el('th', h);
      th.scope = 'col';
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    tbl.appendChild(thead);

    const tbody = el('tbody');
    if (!rows || rows.length === 0) {
      const erow = el('tr');
      const td = el('td', emptyMsg, 'muted');
      td.colSpan = headers.length;
      erow.appendChild(td);
      tbody.appendChild(erow);
    } else {
      rows.forEach(function (cells) {
        const trNode = el('tr');
        cells.forEach(function (cell) {
          const td = el('td');
          if (cell instanceof Node) {
            td.appendChild(cell);
          } else {
            td.textContent = cell === undefined || cell === null ? '—' : String(cell);
          }
          trNode.appendChild(td);
        });
        tbody.appendChild(trNode);
      });
    }
    tbl.appendChild(tbody);
    container.replaceChildren(tbl);
  }

  async function apiGet(path, viewName) {
    const resp = await fetch(path, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    });
    const data = await resp.json();
    if (!resp.ok) {
      const msg = data && data.error && data.error.message ? data.error.message : 'Request failed';
      throw new Error(msg);
    }
    if (viewName) recordPresence(viewName, data, resp.headers);
    return data;
  }

  function renderTree(view) {
    const nodes = view.nodes || [];
    const rows = nodes.map(function (n) {
      return [
        n.instance_id || '—',
        n.life_id || '—',
        n.parent_life_id || '—',
        'L' + String(n.level || 0),
        n.role || '—',
        n.state || '—',
        n.configured ? 'configured' : 'dynamic',
        n.live ? 'live' : 'inactive'
      ];
    });
    renderTable(
      'tree-content',
      ['Instance', 'Life ID', 'Parent Life', 'Level', 'Role', 'State', 'Kind', 'Live'],
      rows,
      'No tree nodes recorded.'
    );
  }

  function renderLifecycle(view) {
    const lanes = view.lanes || [];
    const rows = lanes.map(function (l) {
      return [
        l.life_id,
        l.name,
        l.parent_life_id || '—',
        'L' + String(l.level),
        l.role,
        String(l.run),
        l.state,
        l.session ? l.session.driver : '—',
        l.model,
        l.cleaned ? 'cleaned' : 'active',
        String(l.last_seq)
      ];
    });
    renderTable(
      'lifecycle-content',
      ['Life ID', 'Name', 'Parent', 'Level', 'Role', 'Run', 'State', 'Driver', 'Model', 'Cleaned', 'Seq'],
      rows,
      'No lanes recorded.'
    );
  }

  function renderRaw(view) {
    const records = view.records || [];
    const gaps = view.gaps || [];
    const messages = view.messages || [];
    const rows = [];
    records.forEach(function (r) {
      const pre = el('pre', r.data ? r.data.id + ' (' + r.data.sha256 + ')' : '', 'inert-raw');
      rows.push([
        'capture',
        r.target ? r.target.life_id + '#' + String(r.target.run) : '—',
        r.stream,
        String(r.offset),
        r.primary ? 'primary' : ('supplementary:' + (r.replacement_of || '')),
        r.coverage,
        pre
      ]);
    });
    gaps.forEach(function (g) {
      const endText = g.end_offset !== undefined && g.end_offset !== null ? String(g.end_offset) : 'open';
      rows.push([
        'gap',
        g.target ? g.target.life_id + '#' + String(g.target.run) : '—',
        g.stream,
        String(g.start_offset) + '..' + endText,
        'gap',
        g.reason,
        el('pre', g.observed_at, 'inert-raw')
      ]);
    });
    messages.forEach(function (m) {
      const sender = m.sender ? (m.sender.kind + ':' + m.sender.id) : '—';
      rows.push([
        'mail',
        m.recipient_life_id || '—',
        m.source,
        String(m.queued_seq),
        sender,
        m.status,
        el('pre', m.content ? (m.content.id + ' (' + m.content.sha256 + ')') : '', 'inert-raw')
      ]);
    });
    renderTable(
      'raw-content',
      ['Kind', 'Target', 'Stream / Source', 'Offset / Seq', 'Provenance', 'Status / Coverage', 'Object'],
      rows,
      'No raw capture records, gaps, or mail.'
    );
  }

  function renderDecisions(view) {
    const list = view.decisions || [];
    const rows = list.map(function (d) {
      const src = d.source ? (d.source.path + ' @g' + String(d.source.generation) + ' (' + d.source.sha256 + ')') : '—';
      return [
        d.id,
        el('pre', d.text, 'inert-raw'),
        src,
        d.effective_at,
        d.binding ? 'binding' : 'reminder'
      ];
    });
    renderTable(
      'decisions-content',
      ['ID', 'Decision Text (Inert)', 'Provenance Source', 'Effective At', 'Scope'],
      rows,
      'No authoritative decisions recorded.'
    );
  }

  function renderRefusals(view) {
    const counts = view.counts || [];
    const rows = counts.map(function (c) {
      return [
        c.rule_id,
        'L' + String(c.level),
        String(c.refused),
        String(c.warned),
        String(c.unscored),
        String(c.critical_unscored),
        c.unknown_coverage ? 'unknown_coverage' : 'complete'
      ];
    });
    renderTable(
      'refusals-content',
      ['Rule ID', 'Level', 'Refused', 'Warned', 'Unscored', 'Critical Unscored', 'Coverage'],
      rows,
      'No refusal counts recorded.'
    );
  }

  function renderPlugins(view) {
    const list = view.resources || [];
    const rows = list.map(function (p) {
      return [
        p.id,
        p.path,
        p.version,
        p.sha256,
        p.declared ? 'declared' : 'undeclared',
        p.verified_loaded ? 'verified_loaded' : 'not_loaded',
        p.approval_id || '—'
      ];
    });
    renderTable(
      'plugins-content',
      ['ID', 'Path', 'Version', 'SHA-256', 'Declared', 'Verified Loaded', 'Approval'],
      rows,
      'No plugins recorded.'
    );
  }

  function renderResources(view) {
    const list = view.resources || [];
    const rows = list.map(function (r) {
      return [
        r.id,
        r.kind,
        r.path,
        r.version,
        r.sha256,
        r.approval_id || '—',
        r.observed_at
      ];
    });
    renderTable(
      'resources-content',
      ['ID', 'Kind', 'Path', 'Version', 'SHA-256', 'Approval ID', 'Observed At'],
      rows,
      'No org scripts or tools recorded.'
    );
  }

  function renderApprovals(view) {
    const changes = view.changes || [];
    const approvals = new Map();
    (view.approvals || []).forEach(function (a) {
      approvals.set(a.change_id, a);
      if (a.simulated_presence) simulatedApprovals.add(a.id);
    });
    const apps = new Map();
    (view.applications || []).forEach(function (r) {
      apps.set(r.change_id, r);
    });
    const rows = changes.map(function (c) {
      const appr = approvals.get(c.id);
      const app = apps.get(c.id);
      return [
        c.id,
        c.org_id,
        c.requester ? (c.requester.kind + ':' + c.requester.id) : '—',
        String(c.base_generation),
        c.manifest_sha256,
        c.status,
        appr ? appr.id + ' (' + appr.approver_key_id + ')' : '—',
        app ? ('g' + String(app.new_generation) + ' @ ' + app.applied_at) : '—'
      ];
    });
    renderTable(
      'approvals-content',
      ['Change ID', 'Org', 'Requester', 'Base Gen', 'Manifest SHA-256', 'Status', 'Approval', 'Application'],
      rows,
      'No D6 change requests recorded.'
    );
  }

  async function humanRPC(method, params, proof) {
    if (!humanConfig) throw new Error('Load the current registrations before continuing.');
    const request = {protocol: 'laneboss.rpc.v2', schema: 2, config: humanConfig,
      request_id: requestID('req-'), idempotency_key: requestID('idem-'), method, params};
    if (proof) request.proof = proof;
    request.request_sha256 = await digestRequest(humanConfig, method, params);
    const response = await fetch('/api/v2/rpc', {method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)});
    const value = await response.json();
    if (!response.ok || value.error) throw new Error(value.error && value.error.message || 'Human enrollment request refused.');
    return value.result;
  }

  function deviceBytes(value) {
    return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  }

  function deviceBase64(value) {
    let text = '';
    for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
    return btoa(text);
  }

  async function humanAction(params) {
    const target = params.invite_id || params.principal_id || humanConfig;
    const digest = await digestRequest(humanConfig, 'human.enroll', params);
    const challenge = await humanRPC('human.challenge', {method: 'human.enroll', target_id: target,
      request_sha256: digest, base_generation: params.expected_generation || 0});
    if (challenge.origin !== window.location.origin || !navigator.credentials) throw new Error('Use your security key on the enrolled HTTPS origin.');
    const credential = await navigator.credentials.get({publicKey: {challenge: deviceBytes(challenge.challenge),
      rpId: challenge.rp_id, userVerification: 'required', timeout: 120000}});
    if (!credential || credential.type !== 'public-key' || !credential.response) throw new Error('Security-key confirmation did not complete.');
    const hash = await crypto.subtle.digest('SHA-256', credential.rawId);
    const keyID = 'credential-' + Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
    const proof = await humanRPC('human.confirm', {challenge_id: challenge.id, credential_id: keyID,
      client_data_json: deviceBase64(credential.response.clientDataJSON),
      authenticator_data: deviceBase64(credential.response.authenticatorData), signature: deviceBase64(credential.response.signature)});
    return humanRPC('human.enroll', params, proof);
  }

  async function refreshHumans() {
    const view = await apiGet('/api/v2/humans', 'humans');
    renderHumans(view);
  }

  function renderHumans(view) {
    humanConfig = view.config;
    const rows = (view.registrations || []).map(function (item) {
      const actions = el('div');
      const choices = item.state === 'pending' ? ['approve', 'reject'] : item.state === 'active' ? ['revoke'] : [];
      choices.forEach(function (action) {
        const button = el('button', action.charAt(0).toUpperCase() + action.slice(1));
        button.type = 'button';
        button.addEventListener('click', async function () {
          button.disabled = true;
          try {
            const text = action === 'approve' ? 'Approve this exact key fingerprint?\n' + item.fingerprint : action + ' this human registration?';
            if (!window.confirm(text)) return;
            const params = action === 'revoke' ? {action, principal_id: item.principal_id, expected_generation: item.enrollment_generation}
              : {action, invite_id: item.id, fingerprint: item.fingerprint, expected_generation: item.generation};
            await humanAction(params);
            await refreshHumans();
            byId('humans-error').textContent = '';
          } catch (error) { byId('humans-error').textContent = error.message; }
          finally { button.disabled = false; }
        });
        actions.appendChild(button);
      });
      return [item.principal_id, item.fingerprint, item.state, item.can_approve ? 'May approve' : 'Human', actions];
    });
    renderTable('humans-content', ['Principal', 'Key fingerprint (SHA-256)', 'State', 'Rights', 'Action'], rows, 'No later human registrations.');
  }

  async function refreshAll() {
    const specs = [
      ['tree', '/api/v2/tree', renderTree],
      ['lifecycle', '/api/v2/lifecycle', renderLifecycle],
      ['raw', '/api/v2/raw', renderRaw],
      ['decisions', '/api/v2/decisions', renderDecisions],
      ['refusals', '/api/v2/refusals', renderRefusals],
      ['plugins', '/api/v2/plugins', renderPlugins],
      ['resources', '/api/v2/resources', renderResources],
      ['approvals', '/api/v2/approvals', renderApprovals],
      ['humans', '/api/v2/humans', renderHumans]
    ];
    await Promise.all(specs.map(async function (item) {
      const name = item[0], url = item[1], fn = item[2];
      const errNode = byId(name + '-error');
      try {
        const data = await apiGet(url, name);
        fn(data);
        if (errNode) errNode.textContent = '';
      } catch (err) {
        if (errNode) errNode.textContent = err.message;
      }
    }));
    // Approval/application provenance can arrive after resource views.
    // Repaint the loaded rows after resolving those references.
    refreshPresence();
    specs.forEach(function (item) {
      const entry = viewData.get(item[0]);
      if (entry) item[2](entry.value);
    });
    document.documentElement.dataset.loaded = 'true';
    pendingEvents.splice(0).forEach(applyLiveEvent);
  }

  function applyLiveEvent(event) {
    if (!event || event.origin !== 'service') return;
    const provenance = event.payload || {};
    if (provenance.approval && provenance.approval.simulated_presence && provenance.approval.id) simulatedApprovals.add(provenance.approval.id);
    if (provenance.receipt && provenance.receipt.simulated_presence && provenance.receipt.approval_id) simulatedApprovals.add(provenance.receipt.approval_id);
    if (hasSimulatedPresence(event)) viewPresence.set('events', true);
    refreshPresence();
    [['resources', renderResources], ['plugins', renderPlugins]].forEach(function (item) {
      const cached = viewData.get(item[0]);
      if (cached) item[1](cached.value);
    });
    const entry = viewData.get('lifecycle');
    const treeEntry = viewData.get('tree');
    if (!entry || !treeEntry) {
      if (pendingEvents.length < 256) pendingEvents.push(event);
      return;
    }
    const payload = event.payload || {};
    const id = event.life_id || (payload.lane && payload.lane.life_id);
    if (!id) return;
    const lanes = entry.value.lanes || [];
    const index = lanes.findIndex(function (lane) { return lane.life_id === id; });
    const current = index < 0 ? null : lanes[index];
    if (current && event.seq <= current.last_seq) return;
    let next = current && Object.assign({}, current);
    switch (event.kind) {
      case 'lane.created': case 'lane.adopted': case 'launch.prepared':
      case 'lane.started': case 'lane.resumed':
        if (!payload.lane || payload.lane.life_id !== id) return;
        next = Object.assign({}, payload.lane);
        if (event.kind === 'lane.created' || event.kind === 'launch.prepared') next.state = 'preparing';
        if (event.kind === 'lane.started' || event.kind === 'lane.resumed') next.state = 'running';
        break;
      case 'lane.state':
        if (!next || !payload.to) return;
        next.state = payload.to;
        if (typeof payload.generation === 'number' && payload.generation > 0) next.generation = payload.generation;
        break;
      case 'lane.stopping':
        if (!next) return;
        next.state = 'stopping';
        if (typeof payload.generation === 'number' && payload.generation > 0) next.generation = payload.generation;
        break;
      case 'lane.ended':
        if (!next) return;
        const observed = payload.observation || {};
        next.state = observed.state === 'unknown' || observed.survivors == null || observed.survivors > 0
          ? 'lost' : (payload.profile_continuation ? 'profile_wait' : 'verifying');
        next.budget_remaining = payload.budget_remaining;
        break;
      case 'lane.policy':
        if (!next || payload.from_generation !== next.policy_generation || payload.grant_set_id !== next.grant_set_id ||
            !(payload.to_generation > payload.from_generation) || payload.lane_generation !== next.generation + 1) return;
        next.policy_generation = payload.to_generation;
        next.generation = payload.lane_generation;
        break;
      case 'lane.cleaned':
        if (!next) return;
        next.cleaned = true;
        break;
      case 'lane.lost':
        if (!next) return;
        next.state = 'lost';
        break;
      default:
        return;
    }
    next.last_seq = event.seq;
    next.simulated_presence = Boolean((current && current.simulated_presence) || hasSimulatedPresence(event));
    if (index < 0) lanes.push(next);
    else lanes[index] = next;
    entry.value.lanes = lanes;
    const nodes = treeEntry.value.nodes || [];
    let node = nodes.find(function (item) { return item.life_id === id; });
    if (!node) {
      node = {life_id: id, configured: false};
      nodes.push(node);
    }
    Object.assign(node, {parent_life_id: next.parent_life_id, level: next.level, role: next.role, state: next.state,
      simulated_presence: next.simulated_presence,
      live: !next.cleaned && ['preparing', 'running', 'stopping', 'profile_wait', 'idle'].includes(next.state)});
    treeEntry.value.nodes = nodes;
    treeEntry.value.last_seq = Math.max(treeEntry.value.last_seq || 0, event.seq);
    refreshPresence();
    renderLifecycle(entry.value);
    renderTree(treeEntry.value);
  }

  function connectEvents() {
    if (typeof EventSource === 'undefined') return;
    const es = new EventSource('/api/v2/events?follow=true');
    es.onmessage = function (message) {
      let frame;
      try {
        frame = JSON.parse(message.data);
      } catch (error) {
        const status = byId('lifecycle-error');
        if (status) status.textContent = 'Invalid live event frame.';
        es.close();
        return;
      }
      if (frame.error) {
        const status = byId('lifecycle-error');
        if (status) status.textContent = frame.error.message || 'Live updates ended.';
      }
      // Background events update retained data; they never issue foreground
      // view reads that could refresh the human idle deadline.
      if (frame.event) applyLiveEvent(frame.event);
      if (frame.end && frame.error && ['unauthenticated', 'forbidden', 'deadline', 'deadline_exceeded'].includes(frame.error.code)) es.close();
    };
  }

  function setupControls() {
    const invite = byId('human-invite');
    if (invite) invite.addEventListener('click', async function () {
      invite.disabled = true;
      try {
        const result = await humanAction({action: 'invite', role: 'human'});
        byId('human-token').textContent = 'Share this invitation privately; it expires at ' + result.expires_at + ': ' + result.token;
        byId('humans-error').textContent = '';
      } catch (error) { byId('humans-error').textContent = error.message; }
      finally { invite.disabled = false; }
    });
    const refresh = byId('human-refresh');
    if (refresh) refresh.addEventListener('click', async function () {
      try { await refreshHumans(); byId('humans-error').textContent = ''; }
      catch (error) { byId('humans-error').textContent = error.message; }
    });
    const themeSel = byId('theme-choice');
    if (themeSel) {
      themeSel.addEventListener('change', function () {
        if (themeSel.value === 'system') {
          delete document.documentElement.dataset.theme;
        } else {
          document.documentElement.dataset.theme = themeSel.value;
        }
      });
    }
    const langSel = byId('language-choice');
    if (langSel) {
      langSel.addEventListener('change', function () {
        currentLocale = langSel.value;
        document.documentElement.lang = currentLocale;
        document.querySelectorAll('[data-i18n]').forEach(function (node) {
          const k = node.getAttribute('data-i18n');
          node.textContent = tr(k);
        });
      });
    }
    const dialog = byId('shortcut-panel');
    const closeBtn = byId('shortcut-close');
    if (closeBtn && dialog) {
      closeBtn.addEventListener('click', function () {
        dialog.close();
      });
    }
    document.addEventListener('keydown', function (ev) {
      if (ev.target.closest('input,textarea,select')) return;
      if (ev.key === '?' && dialog) {
        ev.preventDefault();
        if (dialog.open) dialog.close();
        else dialog.showModal();
      }
    });
  }

  readBootstrap();
  setupControls();
  (async function start() {
    try {
      await openSession();
      await refreshAll();
      connectEvents();
    } catch (error) {
      const status = byId('tree-error');
      if (status) status.textContent = error.message;
    }
  })();
})();
