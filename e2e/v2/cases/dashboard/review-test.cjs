// Execute only on the authorized Linux test machine. This drives app.js with
// an inert DOM and service-frame fixture; it makes no native/browser claim.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener() {}
}

async function load(mode) {
  const targets = new Map();
  let events;
  let fetches = 0;
  class Events {
    constructor() { events = this; this.closed = false; }
    close() { this.closed = true; }
  }
  for (const name of ['tree', 'lifecycle', 'raw', 'decisions', 'refusals', 'plugins', 'resources', 'approvals']) {
    targets.set(name + '-content', new Element('div'));
    targets.set(name + '-error', new Element('p'));
  }
  targets.set('presence-summary', new Element('p'));
  targets.set('bootstrap-nonce', new Element('code'));
  const storage = new Map();
  const window = {
    location: {hash: '', pathname: '/', search: ''},
    history: {replaceState() { throw new Error('unexpected fragment replacement'); }},
    confirm: () => false,
  };
  const sessionStorage = {
    getItem: (key) => storage.has(key) ? storage.get(key) : null,
    setItem: (key, value) => storage.set(key, String(value)),
  };
  const crypto = {getRandomValues: (bytes) => { for (let i = 0; i < bytes.length; i++) bytes[i] = i + 1; return bytes; }};
  const document = {getElementById: (id) => targets.get(id) || null, createElement: (tag) => new Element(tag),
    addEventListener() {}, documentElement: {dataset: {}}};
  const views = {
    tree: {nodes: [{life_id: 'life', level: 3, role: 'executor', state: 'running', live: true}]},
    lifecycle: {lanes: [{life_id: 'life', name: 'lane', level: 3, role: 'executor', run: 1, state: 'running', generation: 7, policy_generation: 4, grant_set_id: 'grants', last_seq: 1}]},
    raw: {records: [], messages: [], gaps: []}, decisions: {decisions: []}, refusals: {counts: []}, plugins: {resources: []},
    resources: {resources: [{id: 'resource', kind: 'script', path: 'scripts/example.sh', approval_id: mode === 'live' ? 'later' : ''}]},
    approvals: mode === 'idless' ? {changes: [], approvals: [{id: '', simulated_presence: true}], applications: [{simulated_presence: true}]} : {changes: [], approvals: [], applications: []},
  };
  const source = fs.readFileSync(path.join(__dirname, '..', '..', '..', '..', 'web', 'v2', 'app.js'), 'utf8').replace('/* LOCALE */', '{}');
  vm.runInNewContext(source, {document, window, sessionStorage, crypto,
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
    Node: Element, EventSource: Events,
    fetch: async (url) => { fetches++; return {ok: true, headers: {get: () => 'not_proven'}, json: async () => views[url.split('/').at(-1)]}; }
  }, {filename: 'app.js'});
  for (let turn = 0; document.documentElement.dataset.loaded !== 'true' && turn < 20; turn++) await new Promise(setImmediate);
  assert.equal(document.documentElement.dataset.loaded, 'true', 'review renderer did not finish fixture reads');
  const send = (frame) => events.onmessage({data: JSON.stringify(frame)});
  const text = (node) => node.textContent + node.children.map(text).join(' ');
  return {targets, views, events, send, text, fetches: () => fetches};
}

async function declineBootstrap() {
  const targets = new Map();
  for (const name of ['tree', 'lifecycle', 'raw', 'decisions', 'refusals', 'plugins', 'resources', 'approvals']) {
    targets.set(name + '-content', new Element('div'));
    targets.set(name + '-error', new Element('p'));
  }
  targets.set('presence-summary', new Element('p'));
  targets.set('bootstrap-nonce', new Element('code'));
  const storage = new Map();
  const order = [];
  let confirmText = '';
  let sessionCalls = 0;
  const window = {
    location: {hash: '#bootstrap=token-b', pathname: '/', search: ''},
    history: {replaceState(_state, _title, url) { order.push('replaceState'); this.url = url; window.location.hash = ''; }},
    confirm: (message) => { order.push('confirm'); confirmText = message; return false; },
  };
  const sessionStorage = {
    getItem: (key) => storage.has(key) ? storage.get(key) : null,
    setItem: (key, value) => storage.set(key, String(value)),
  };
  const crypto = {getRandomValues: (bytes) => { for (let i = 0; i < bytes.length; i++) bytes[i] = i + 1; return bytes; }};
  const document = {
    getElementById: (id) => targets.get(id) || null,
    createElement: (tag) => new Element(tag),
    addEventListener() {},
    documentElement: {dataset: {}},
  };
  const info = {config: 'cfg-b', actor: {kind: 'human', id: 'owner-b'}, proof: {id: 'proof-b'}};
  const fetch = async (url, options = {}) => {
    order.push('fetch');
    if (url === '/api/v2/bootstrap') {
      assert.equal(options.headers['X-Laneboss-Dashboard-Bootstrap'], 'token-b');
      assert.match(options.headers['X-Laneboss-Dashboard-Nonce'], /^[A-Za-z0-9_-]{22}$/,
        'preview omitted the browser nonce');
      return {ok: true, headers: {get: () => ''}, json: async () => info};
    }
    if (url === '/api/v2/rpc') {
      sessionCalls++;
      return {ok: true, headers: {get: () => ''}, json: async () => ({})};
    }
    throw new Error('unexpected bootstrap fetch ' + url);
  };
  const source = fs.readFileSync(path.join(__dirname, '..', '..', '..', '..', 'web', 'v2', 'app.js'), 'utf8').replace('/* LOCALE */', '{}');
  vm.runInNewContext(source, {document, window, sessionStorage, crypto,
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'), fetch, Node: Element,
    EventSource: class { close() {} }}, {filename: 'app.js'});
  for (let turn = 0; !targets.get('tree-error').textContent && turn < 20; turn++) await new Promise(setImmediate);
  assert.equal(window.location.hash, '', 'bootstrap fragment was not stripped');
  assert.deepEqual(order, ['replaceState', 'fetch', 'confirm'], 'bootstrap work ran in the wrong order');
  assert.match(targets.get('bootstrap-nonce').textContent, /^[A-Za-z0-9_-]{22}$/, 'bootstrap page hid its browser nonce');
  assert.equal(confirmText, 'Sign in as human:owner-b in configuration cfg-b?', 'preview identity was not shown');
  assert.equal(sessionCalls, 0, 'declined confirmation still called human.session');
}

module.exports = async function reviewChecks() {
  const stream = await load('stream');
  const initialFetches = stream.fetches();
  stream.send({event: {origin: 'service', kind: 'lane.stopping', life_id: 'life', run: 1, seq: 2, payload: {}}});
  assert.equal(stream.views.lifecycle.lanes[0].state, 'stopping', 'stopping frame without to was dropped');
  assert.equal(stream.views.lifecycle.lanes[0].generation, 7, 'stopping frame erased the current generation');
  stream.send({event: {origin: 'service', kind: 'lane.policy', life_id: 'life', seq: 3,
    payload: {from_generation: 4, to_generation: 4, lane_generation: 8, grant_set_id: 'grants'}}});
  assert.equal(stream.views.lifecycle.lanes[0].last_seq, 2, 'browser admitted a nonadvancing policy event');
  stream.send({event: {origin: 'service', kind: 'lane.policy', life_id: 'life', seq: 4,
    payload: {from_generation: 4, to_generation: 5, lane_generation: 10, grant_set_id: 'grants'}}});
  assert.equal(stream.views.lifecycle.lanes[0].last_seq, 2, 'browser admitted a policy generation jump');
  stream.send({event: {origin: 'service', kind: 'lane.policy', life_id: 'life', seq: 5,
    payload: {from_generation: 4, to_generation: 5, lane_generation: 8, grant_set_id: 'grants'}}});
  assert.equal(stream.views.lifecycle.lanes[0].policy_generation, 5, 'browser lost a valid policy advance');
  stream.send({end: true, error: {code: 'unavailable', message: 'Reconnect with the saved cursor.'}});
  assert.equal(stream.events.closed, false, 'SSE overflow disabled browser reconnect');
  stream.send({end: true, error: {code: 'unauthenticated', message: 'Authenticate again.'}});
  assert.equal(stream.events.closed, true, 'SSE authentication failure kept reconnecting');
  assert.equal(stream.fetches(), initialFetches, 'live projection issued an authenticated background read');

  const idless = await load('idless');
  assert.equal(idless.text(idless.targets.get('resources-content')).includes('presence=simulated'), false,
    'empty approval identifier tainted an unrelated resource view');
  assert.equal(idless.text(idless.targets.get('lifecycle-content')).includes('presence=simulated'), false,
    'empty approval identifier tainted an unrelated lifecycle view');

  const live = await load('live');
  assert.equal(live.targets.get('presence-summary').textContent, 'presence=not_proven; human_approval=not_proven');
  const before = live.fetches();
  live.send({event: {origin: 'service', kind: 'org.change.approved', seq: 2,
    payload: {change: {id: 'change'}, approval: {id: 'later', change_id: 'change', simulated_presence: true}}}});
  assert.equal(live.targets.get('presence-summary').textContent, 'presence=simulated; human_approval=not_proven',
    'live service event lost simulated provenance');
  assert.equal(live.text(live.targets.get('resources-content')).includes('presence=simulated'), true,
    'live approval failed to mark its dependent resource');
  assert.equal(live.fetches(), before, 'presence update issued an authenticated background read');
  await declineBootstrap();
};
