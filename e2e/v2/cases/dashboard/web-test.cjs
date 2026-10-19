// Execute only on the disposable Linux test machine. This runs the actual web
// renderer with an inert DOM fixture; it makes no native/authentication claim.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.textContent = '';
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener() {}
}

async function main() {
  const targets = new Map();
  let eventSource;
  let fetches = 0;
  class FixtureEvents {
    constructor() { eventSource = this; }
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
  const document = {
    getElementById: (id) => targets.get(id) || null,
    createElement: (tag) => new Element(tag),
    addEventListener() {},
    documentElement: {dataset: {}}
  };
  const views = {
    tree: {nodes: [{life_id: 'life', level: 3, role: 'executor', state: 'running', live: true}]},
    lifecycle: {lanes: [{life_id: 'life', name: 'lane', level: 3, role: 'executor', run: 1, state: 'running', last_seq: 1}]},
    raw: {records: [], messages: [], gaps: []},
    decisions: {decisions: []},
    refusals: {counts: []},
    plugins: {resources: []},
    resources: {resources: [{id: 'resource', kind: 'script', path: 'scripts/example.sh', approval_id: 'approval'}]},
    approvals: {
      changes: [{id: 'change', org_id: 'org', base_generation: 1, status: 'approved'}],
      approvals: [{id: 'approval', change_id: 'change', simulated_presence: true}],
      applications: [{id: 'application', change_id: 'change', approval_id: 'approval', new_generation: 2}]
    }
  };
  const sourcePath = path.resolve(__dirname, '../../../../web/v2/app.js');
  const source = fs.readFileSync(sourcePath, 'utf8').replace('/* LOCALE */', '{}');
  vm.runInNewContext(source, {
    document, window, sessionStorage, crypto,
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
    Node: Element, EventSource: FixtureEvents,
    fetch: async (url) => {
      fetches++;
      const name = url.split('/').at(-1);
      if (name === 'approvals') await new Promise(setImmediate);
      return {ok: true, headers: {get: () => 'not_proven'}, json: async () => views[name]};
    }
  }, {filename: 'app.js'});
  for (let turn = 0; document.documentElement.dataset.loaded !== 'true' && turn < 20; turn++) {
    await new Promise(setImmediate);
  }
  assert.equal(document.documentElement.dataset.loaded, 'true', 'renderer did not finish fixture reads');
  assert.match(targets.get('bootstrap-nonce').textContent, /^[A-Za-z0-9_-]{22}$/, 'fresh page did not display a 128-bit browser nonce');
  assert.equal(targets.get('presence-summary').textContent,
    'presence=simulated; human_approval=not_proven',
    'aggregate hid simulated presence');
  const table = targets.get('resources-content').children[0];
  const cells = table.children[1].children[0].children;
  assert.equal(cells.at(-1).textContent,
    'presence=simulated; human_approval=not_proven',
    'dependent resource lost simulated presence');
  const initialFetches = fetches;
  eventSource.onmessage({data: JSON.stringify({event: {origin: 'service', kind: 'lane.state', life_id: 'life',
    run: 1, seq: 2, payload: {from: 'running', to: 'verifying', generation: 2}}})});
  await new Promise(setImmediate);
  assert.equal(fetches, initialFetches, 'SSE background event performed foreground fetch');
  const liveCells = targets.get('lifecycle-content').children[0].children[1].children[0].children;
  assert.equal(liveCells[6].textContent, 'verifying', 'SSE event did not update lifecycle');
  eventSource.onmessage({data: JSON.stringify({end: true, error: {code: 'unauthenticated', message: 'human read session expired'}})});
  assert.equal(eventSource.closed, true, 'expired SSE kept reconnecting');
  assert.equal(fetches, initialFetches, 'SSE background event performed foreground fetch');
  await require('./enrollment-test.cjs')();
  await require('./review-test.cjs')();
  console.log('PASS: dashboard presence rows');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
