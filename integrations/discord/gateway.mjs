#!/usr/bin/env node
// Receive-only Discord gateway. Node 22+, no third-party modules.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

const ID = /^[1-9][0-9]{0,19}$/;
const INTENTS = 1 | 2 | 512 | 32768; // Guilds, members, guild messages, content.
const MAX_PACKET = 1024 * 1024;
class GatewayError extends Error {}
const fail = (reason) => { throw new GatewayError(reason); };
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const id = (value) => typeof value === 'string' && ID.test(value);
const log = (reason) => process.stderr.write('discord-gateway: ' + reason + '\n');
const drop = (reason) => { log('drop: ' + reason); return null; };

function readConfig(org, launcher) {
  // The reader needs no credential, so do not give it the gateway's environment.
  const env = {};
  for (const name of ['HOME', 'PATH', 'LANG', 'LC_ALL', 'LANEBOSS_CONFIG']) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  const result = spawnSync(launcher, ['org', 'channel', 'read', org, '--json'],
    { env, encoding: 'utf8', timeout: 20000, maxBuffer: MAX_PACKET });
  if (result.error || result.status !== 0) {
    fail('launcher could not read Discord configuration; run laneboss org channel read ORG --json');
  }
  let config;
  try { config = JSON.parse(result.stdout); } catch {
    fail('launcher returned invalid Discord configuration');
  }
  if (!object(config) || config.schema_version !== 1 || !id(config.guild_id) ||
      typeof config.token_env !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(config.token_env) ||
      !object(config.roles) || Object.keys(config.roles).length === 0 ||
      !path.isAbsolute(config.org_dir) || !path.isAbsolute(config.lock_file) ||
      !path.isAbsolute(config.gateway_state_file)) fail('launcher returned invalid Discord configuration');
  return config;
}

function endpoints() {
  const override = process.env.LANEBOSS_TEST_DISCORD_BASE_URL;
  if (override === undefined) return { api: 'https://discord.com/api/v10', testOrigin: null };
  // Match the input bytes too: URL normalization must not accept another host.
  const match = /^(http|ws):\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.exec(override);
  if (!match || Number(match[2]) > 65535) {
    fail('LANEBOSS_TEST_DISCORD_BASE_URL requires a loopback http://127.0.0.1:PORT or ws://127.0.0.1:PORT origin');
  }
  const origin = '127.0.0.1:' + match[2];
  return { api: 'http://' + origin + '/api/v10', testOrigin: origin };
}

function gatewayURL(value, endpoint) {
  let url;
  try { url = new URL(value); } catch { fail('Discord returned an invalid gateway URL'); }
  if (url.username || url.password || url.hash || url.search) fail('Discord returned an invalid gateway URL');
  const allowed = endpoint.testOrigin
    ? url.protocol === 'ws:' && url.host === endpoint.testOrigin
    : url.protocol === 'wss:' && !url.port &&
      (url.hostname === 'gateway.discord.gg' || /^gateway-[a-z0-9-]+\.discord\.gg$/.test(url.hostname));
  if (!allowed) fail('Discord gateway URL is outside the allowed endpoint');
  url.search = '?v=10&encoding=json';
  return url.href;
}

function discover(endpoint, token, signal) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint.api + '/gateway/bot');
    const request = (url.protocol === 'https:' ? https : http).get(url, {
      signal, timeout: 20000,
      headers: { Authorization: 'Bot ' + token, 'User-Agent': 'DiscordBot (laneboss, 0.7.0)' },
    }, (response) => {
      // Never follow redirects, echo an error body, or consult proxy settings.
      if (response.statusCode !== 200) {
        response.resume();
        reject(new GatewayError('Discord gateway discovery failed (HTTP ' + response.statusCode + ')'));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_PACKET) request.destroy(new GatewayError('Discord discovery response is too large'));
        else chunks.push(chunk);
      });
      response.on('error', () => reject(new GatewayError('Discord gateway discovery failed')));
      response.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!object(data) || typeof data.url !== 'string') fail('Discord discovery response is invalid');
          gatewayURL(data.url, endpoint);
          resolve(data.url);
        } catch (error) {
          reject(error instanceof GatewayError ? error : new GatewayError('Discord discovery response is invalid'));
        }
      });
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => reject(new GatewayError('Discord gateway discovery failed')));
  });
}

function prepareParent(config, filename) {
  const relative = path.relative(config.org_dir, filename);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
    fail('gateway state paths must stay inside the validated org');
  }
  let current = config.org_dir;
  for (const part of path.dirname(relative).split(path.sep)) {
    if (part === '.') continue;
    current = path.join(current, part);
    try { fs.mkdirSync(current, { mode: 0o700 }); } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const info = fs.lstatSync(current);
    if (!info.isDirectory() || info.isSymbolicLink()) fail('gateway state directories must not be symbolic links');
  }
}

function privateFile(filename) {
  let info;
  try { info = fs.lstatSync(filename); } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid() ||
      (info.mode & 0o077) !== 0 || info.nlink !== 1) fail('gateway files must be private, owned regular files without links');
  return true;
}

function atomicJSON(config, filename, value) {
  prepareParent(config, filename);
  privateFile(filename);
  const temporary = filename + '.tmp-' + randomUUID();
  const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const bytes = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
    if (fs.writeSync(fd, bytes, 0, bytes.length) !== bytes.length) fail('short gateway state write');
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  try {
    fs.renameSync(temporary, filename);
  } catch (error) {
    fs.unlinkSync(temporary);
    throw error;
  }
}

function acquireLock(config) {
  prepareParent(config, config.lock_file);
  let fd;
  try {
    fd = fs.openSync(config.lock_file, fs.constants.O_WRONLY | fs.constants.O_CREAT |
      fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    if (error.code === 'EEXIST') fail('another gateway is already running for this org, or a stale gateway lock remains');
    throw error;
  }
  const held = fs.fstatSync(fd);
  const release = () => {
    fs.closeSync(fd);
    const current = fs.lstatSync(config.lock_file);
    if (current.ino !== held.ino || current.dev !== held.dev) fail('gateway lock changed while held');
    fs.unlinkSync(config.lock_file);
  };
  try { fs.writeSync(fd, String(process.pid) + '\n'); } catch (error) {
    release();
    throw error;
  }
  return release;
}

function loadRoles(config) {
  const channels = new Map();
  for (const [name, role] of Object.entries(config.roles)) {
    if (!object(role) || !id(role.channel_id) || !Array.isArray(role.members) ||
        typeof role.instance !== 'string' || typeof role.channel_name !== 'string' ||
        !path.isAbsolute(role.events_file) || !path.isAbsolute(role.state_file)) {
      fail('launcher returned invalid Discord roles');
    }
    prepareParent(config, role.events_file);
    prepareParent(config, role.state_file);
    const seen = new Set();
    let last = null;
    if (privateFile(role.events_file)) {
      const content = fs.readFileSync(role.events_file, 'utf8');
      if (content && !content.endsWith('\n')) fail('gateway event log has an incomplete line; repair before restarting');
      for (const line of content.split('\n')) {
        if (!line) continue;
        const event = JSON.parse(line);
        if (!object(event) || event.role !== name || event.instance !== role.instance ||
            !id(event.message_id) || seen.has(event.message_id)) fail('gateway event log is invalid');
        seen.add(event.message_id);
        last = event.message_id;
      }
    }
    if (privateFile(role.state_file)) {
      const state = JSON.parse(fs.readFileSync(role.state_file, 'utf8'));
      if (!object(state) || (state.last_message_id !== null &&
          (!id(state.last_message_id) || !seen.has(state.last_message_id)))) fail('gateway role state disagrees with its event log');
    }
    // The append is authoritative after a crash between append and state rename.
    atomicJSON(config, role.state_file, { last_message_id: last });
    channels.set(role.channel_id, { ...role, name, seen, last });
  }
  return channels;
}

function messageToEvent(message, channels, guild) {
  if (!object(message)) return drop('malformed message');
  const role = channels.get(message.channel_id);
  if (!role) return drop('unknown channel');
  if (message.guild_id !== guild) return drop('wrong or missing guild');
  const author = message.author;
  if (!object(author)) return drop('malformed author');
  if (author.bot) return drop('bot sender');
  if (message.webhook_id !== undefined && message.webhook_id !== null) return drop('webhook sender');
  if (!id(author.id) || !id(message.id) || (author.bot !== undefined && typeof author.bot !== 'boolean')) {
    return drop('malformed author or message id');
  }
  const member = message.member === undefined ? {} : message.member;
  if (!object(member) || (member.roles !== undefined &&
      (!Array.isArray(member.roles) || !member.roles.every(id)))) return drop('malformed member metadata');
  const explicit = role.members.find((entry) => entry.user_id === author.id);
  const matching = role.members.filter((entry) => (member.roles || []).includes(entry.role_id));
  const authority = explicit?.authority ||
    (matching.some((entry) => entry.authority === 'decide') ? 'decide' : matching[0]?.authority);
  if (!authority) return drop('unlisted sender');
  const display = [member.nick, author.global_name, author.username]
    .find((value) => typeof value === 'string' && value.length > 0);
  const reference = message.message_reference;
  if (!display || typeof message.content !== 'string' ||
      (reference !== undefined && reference !== null && !object(reference))) return drop('malformed text or reply metadata');
  const reply = reference?.message_id ?? null;
  if (reply !== null && !id(reply)) return drop('malformed reply id');
  return { role: role.name, instance: role.instance,
    channel: { id: role.channel_id, name: role.channel_name },
    author: { id: author.id, display_name: display, authority },
    message_id: message.id, reply_to: reply, text: message.content };
}

function deliver(config, channels, message) {
  const event = messageToEvent(message, channels, config.guild_id);
  if (!event) return;
  const role = channels.get(event.channel.id);
  if (role.seen.has(event.message_id)) { log('drop: duplicate message'); return; }
  privateFile(role.events_file);
  const fd = fs.openSync(role.events_file, fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const line = Buffer.from(JSON.stringify(event) + '\n', 'utf8');
    // Exactly one O_APPEND write. Never retry a partial write as a second line.
    if (fs.writeSync(fd, line, 0, line.length) !== line.length) fail('short gateway event write; repair before restarting');
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  role.seen.add(event.message_id);
  role.last = event.message_id;
  atomicJSON(config, role.state_file, { last_message_id: role.last });
}

class Gateway {
  constructor(config, channels, endpoint, token, signal) {
    Object.assign(this, { config, channels, endpoint, token, signal });
    this.session = null;
    this.sequence = null;
    this.resumeURL = null;
    this.lastIdentify = 0;
  }
  resetSession() { this.session = null; this.sequence = null; this.resumeURL = null; }
  async run() {
    const initial = await discover(this.endpoint, this.token, this.signal);
    let backoff = 1000;
    while (!this.signal.aborted) {
      if (!this.session) {
        const wait = Math.max(0, 5000 - (Date.now() - this.lastIdentify));
        if (wait) await delay(wait, undefined, { signal: this.signal });
      }
      const result = await this.connect(this.resumeURL || initial);
      if (result.error) throw result.error;
      if (this.signal.aborted) break;
      if ([4004, 4010, 4011, 4012, 4013, 4014].includes(result.code)) {
        fail('Discord refused gateway authentication or intents (close ' + result.code + ')');
      }
      if ([4007, 4009].includes(result.code)) this.resetSession();
      log('connection ended; reconnecting');
      if (result.authenticated) backoff = 1000;
      await delay(backoff + Math.floor(Math.random() * 250), undefined, { signal: this.signal });
      backoff = Math.min(backoff * 2, 30000);
    }
  }
  connect(base) {
    return new Promise((resolve) => {
      let socket;
      try { socket = new WebSocket(gatewayURL(base, this.endpoint)); } catch (error) {
        resolve({ error: error instanceof GatewayError ? error : new GatewayError('could not open Discord gateway') });
        return;
      }
      let finished = false;
      let authenticated = false;
      let resuming = false;
      let hello = false;
      let outstanding = false;
      let heartbeatTimer;
      const deadline = setTimeout(() => finish({ code: 0 }), 20000);
      const finish = (result) => {
        if (finished) return;
        finished = true;
        clearTimeout(deadline);
        clearTimeout(heartbeatTimer);
        this.signal.removeEventListener('abort', abort);
        socket.close(1000);
        resolve({ authenticated, ...result });
      };
      const abort = () => finish({ code: 1000 });
      const send = (op, d) => socket.send(JSON.stringify({ op, d }));
      const heartbeat = (scheduled = true) => {
        if (finished) return;
        try {
          if (scheduled && outstanding) { finish({ code: 0 }); return; }
          outstanding = true;
          send(1, this.sequence);
          if (scheduled) heartbeatTimer = setTimeout(heartbeat, interval);
        } catch { finish({ code: 0 }); }
      };
      let interval;
      this.signal.addEventListener('abort', abort, { once: true });
      if (this.signal.aborted) { abort(); return; }
      socket.addEventListener('error', () => finish({ code: 0 }));
      socket.addEventListener('close', (event) => finish({ code: event.code }));
      socket.addEventListener('message', (event) => {
        if (finished) return;
        try {
          if (typeof event.data !== 'string' || Buffer.byteLength(event.data) > MAX_PACKET) {
            drop('malformed gateway packet'); return;
          }
          let packet;
          try { packet = JSON.parse(event.data); } catch { drop('malformed gateway packet'); return; }
          if (!object(packet) || !Number.isInteger(packet.op)) { drop('malformed gateway packet'); return; }
          if (packet.op === 10) {
            interval = packet.d?.heartbeat_interval;
            if (hello || !Number.isFinite(interval) || interval < 1 || interval > 300000) fail('invalid Discord heartbeat interval');
            hello = true;
            heartbeatTimer = setTimeout(heartbeat, Math.floor(Math.random() * interval));
            if (this.session && this.sequence !== null) {
              send(6, { token: this.token, session_id: this.session, seq: this.sequence });
              resuming = true; // Discord replays missed dispatches before RESUMED.
            } else {
              this.lastIdentify = Date.now();
              send(2, { token: this.token, intents: INTENTS,
                properties: { os: process.platform, browser: 'laneboss', device: 'laneboss' } });
            }
          } else if (packet.op === 11) {
            outstanding = false;
          } else if (packet.op === 1 && hello) {
            heartbeat(false);
          } else if (packet.op === 7) {
            finish({ code: 0 });
          } else if (packet.op === 9) {
            if (packet.d !== true) this.resetSession();
            finish({ code: 0 });
          } else if (packet.op === 0) {
            if (!hello || !Number.isSafeInteger(packet.s) || packet.s < 0 || typeof packet.t !== 'string') {
              drop('malformed dispatch'); return;
            }
            if (this.sequence !== null && packet.s <= this.sequence && packet.t !== 'READY') {
              drop('duplicate or stale dispatch'); return;
            }
            if (packet.t === 'READY') {
              if (!object(packet.d) || typeof packet.d.session_id !== 'string' || !packet.d.session_id ||
                  typeof packet.d.resume_gateway_url !== 'string') fail('invalid Discord ready packet');
              gatewayURL(packet.d.resume_gateway_url, this.endpoint);
              this.session = packet.d.session_id;
              this.resumeURL = packet.d.resume_gateway_url;
              authenticated = true;
              clearTimeout(deadline);
              log('ready');
            } else if (packet.t === 'RESUMED' && resuming) {
              authenticated = true;
              resuming = false;
              clearTimeout(deadline);
              log('resumed');
            } else if (!authenticated && !resuming) {
              drop('dispatch before authentication'); return;
            } else if (packet.t === 'MESSAGE_CREATE') {
              deliver(this.config, this.channels, packet.d);
            }
            // Commit the cursor only after synchronous append and state update.
            this.sequence = packet.s;
            atomicJSON(this.config, this.config.gateway_state_file, { last_sequence: this.sequence });
          }
        } catch (error) {
          finish({ error: error instanceof GatewayError ? error : new GatewayError('gateway input or state write failed') });
        }
      });
    });
  }
}

async function main() {
  if (Number(process.versions.node.split('.')[0]) < 22 || typeof WebSocket !== 'function') fail('Node 22 or newer is required');
  let org;
  let launcher = 'laneboss';
  const args = process.argv.slice(2);
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    process.stdout.write('Usage: node integrations/discord/gateway.mjs --org ORG [--launcher PATH]\n');
    return;
  }
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i + 1]) fail('Usage: gateway.mjs --org ORG [--launcher PATH]');
    if (args[i] === '--org' && !org) org = args[i + 1];
    else if (args[i] === '--launcher') launcher = args[i + 1];
    else fail('Usage: gateway.mjs --org ORG [--launcher PATH]');
  }
  if (!org) fail('Usage: gateway.mjs --org ORG [--launcher PATH]');
  const endpoint = endpoints(); // Refuse unsafe overrides before any network call.
  const config = readConfig(org, launcher);
  const token = process.env[config.token_env] || process.env.DISCORD_BOT_TOKEN;
  if (typeof token !== 'string' || !/^[A-Za-z0-9._-]{20,512}$/.test(token)) fail('bot token is missing or invalid in the configured environment');
  const release = acquireLock(config);
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  try {
    const channels = loadRoles(config);
    atomicJSON(config, config.gateway_state_file, { last_sequence: null });
    await new Gateway(config, channels, endpoint, token, controller.signal).run();
  } catch (error) {
    if (!(controller.signal.aborted && error.name === 'AbortError')) throw error;
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    release();
  }
}

main().catch((error) => {
  log(error instanceof GatewayError ? error.message : 'gateway failed; check configuration and private state permissions');
  process.exitCode = 1;
});
