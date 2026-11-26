// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// ThatFellowDev build: who may reach this computer's listeners at all (TCP 47800, the files engines,
// discovery on UDP 47801, the input lane), checked before anything else reads a byte.
//
// The list is <userData>/allow-from.json: ["100.82.128.47", "100.64.0.0/10", ...] (IPv4 addresses or
// CIDRs). No file, or an empty list: everyone, as upstream. Loopback is always allowed, because the
// Bluetooth pipe and a phone's USB cable arrive as 127.0.0.1. Read once; a change needs a restart.
// The listeners stay on 0.0.0.0 so they still start when Tailscale comes up after TwinDesk.
'use strict';

const fs = require('fs');
const path = require('path');

const MAX_FILE = 64 * 1024;
let rules = null; // [{net, mask}] or [] for "everyone"

function ip4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || '').trim());
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((n) => n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function rule(s) {
  const [addr, bits = '32'] = String(s || '').split('/');
  const a = ip4(addr);
  const n = /^\d{1,2}$/.test(bits) ? Number(bits) : -1;
  if (a === null || n < 0 || n > 32) return null;
  const mask = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
  return { net: (a & mask) >>> 0, mask };
}

// list: array of strings; entries that aren't an IPv4 address or CIDR are dropped. A list given but
// left with no valid entry allows only loopback, never everyone.
function set(list) {
  if (!Array.isArray(list) || !list.length) { rules = []; return; }
  rules = list.map(rule).filter(Boolean);
  if (!rules.length) rules = [{ net: 0x7f000000, mask: 0xff000000 }];
}

// The files engine runs in a utilityProcess, where Electron has no app: there the folder main.js
// sets as userData (windows/main.js, mac/main.js) is worked out the same way.
function defaultFile() {
  if (process.env.TWINDESK_ALLOW_FILE) return process.env.TWINDESK_ALLOW_FILE;
  try {
    const { app } = require('electron');
    if (app && app.getPath) return path.join(app.getPath('userData'), 'allow-from.json');
  } catch {}
  const os = require('os');
  const appData = process.platform === 'win32' ? (process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'))
    : process.platform === 'darwin' ? path.join(os.homedir(), 'Library', 'Application Support')
      : (process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'));
  return path.join(process.env.MACSHARE_PROFILE || path.join(appData, 'MacShare'), 'allow-from.json');
}

function load(file = defaultFile()) {
  let list = null;
  try {
    if (file && fs.statSync(file).size <= MAX_FILE) list = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') { console.log('[netallow] unreadable ' + file + ': ' + e.message + ' (loopback only)'); list = ['127.0.0.1']; }
  }
  set(list);
  if (rules.length) console.log('[netallow] ' + rules.length + ' allowed source(s) from ' + file);
}

function ok(address) {
  if (rules === null) load();
  if (!rules.length) return true;
  let a = String(address || '').replace(/^::ffff:/i, '');
  if (a === '::1') return true;
  const v = ip4(a);
  if (v === null) return false; // other IPv6: not on the list
  if ((v & 0xff000000) >>> 0 === 0x7f000000) return true;
  return rules.some((r) => ((v & r.mask) >>> 0) === r.net);
}

// For a net/tls/https server: server.on('connection', NetAllow.guard).
function guard(sock) {
  if (!ok(sock.remoteAddress)) sock.destroy();
}

module.exports = { ok, guard, set, load };
