// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// shared/netallow.js and the listeners that use it: only the listed sources (and loopback) get in.
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const NetAllow = require('../netallow.js');
const P = require('../protocol.js');

(async () => {
  // No list: everyone, as upstream.
  NetAllow.set(null);
  assert.strictEqual(NetAllow.ok('192.168.1.20'), true);

  // A list: exact addresses and CIDRs, IPv4-mapped IPv6, loopback always.
  NetAllow.set(['100.82.128.47', '100.73.162.61/32', '10.9.0.0/16', 'junk']);
  assert.strictEqual(NetAllow.ok('100.82.128.47'), true);
  assert.strictEqual(NetAllow.ok('::ffff:100.73.162.61'), true);
  assert.strictEqual(NetAllow.ok('10.9.200.1'), true);
  assert.strictEqual(NetAllow.ok('100.82.128.48'), false);
  assert.strictEqual(NetAllow.ok('192.168.50.10'), false);
  assert.strictEqual(NetAllow.ok('fe80::1'), false);
  assert.strictEqual(NetAllow.ok('127.0.0.1'), true);
  assert.strictEqual(NetAllow.ok('::1'), true);
  assert.strictEqual(NetAllow.ok(''), false);

  // A list with nothing valid in it: loopback only, never everyone.
  NetAllow.set(['nonsense']);
  assert.strictEqual(NetAllow.ok('100.82.128.47'), false);
  assert.strictEqual(NetAllow.ok('127.0.0.1'), true);

  // The file: missing = everyone; unreadable = loopback only.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netallow-'));
  NetAllow.load(path.join(dir, 'none.json'));
  assert.strictEqual(NetAllow.ok('192.168.1.20'), true);
  fs.writeFileSync(path.join(dir, 'bad.json'), '{not json');
  NetAllow.load(path.join(dir, 'bad.json'));
  assert.strictEqual(NetAllow.ok('100.82.128.47'), false);
  fs.writeFileSync(path.join(dir, 'ok.json'), JSON.stringify(['100.82.128.47']));
  NetAllow.load(path.join(dir, 'ok.json'));
  assert.strictEqual(NetAllow.ok('100.82.128.47'), true);
  assert.strictEqual(NetAllow.ok('100.82.128.1'), false);

  // Discovery (both platforms): an INVITE from a source not on the list is ignored entirely.
  NetAllow.set(['100.82.128.47']);
  for (const [name, make] of [
    ['windows', () => new (require('../../windows/discovery.js').Discovery)({ id: 'self', name: 'PC' })],
    ['mac', () => new (require('../../mac/discovery.js').Discovery)({ macId: 'self', macName: 'Mac', fp: '' })],
  ]) {
    const d = make();
    d._send = () => { throw new Error(name + ': answered a probe from outside the list'); };
    let invites = 0;
    d.on('invite', () => invites++);
    const msg = (t) => Buffer.from(JSON.stringify({ v: P.PROTOCOL_VERSION, t, id: 'peer', name: 'x', os: P.OS.MAC, port: 47800 }));
    d._onMessage(msg(P.T.INVITE), { address: '192.168.50.66', port: 47801 });
    d._onMessage(msg(P.T.PROBE), { address: '192.168.50.66', port: 47801 });
    assert.strictEqual(invites, 0, name + ': invite from outside the list');
    assert.strictEqual(d.found.size, 0, name + ': device recorded from outside the list');
    d._onMessage(msg(P.T.INVITE), { address: '100.82.128.47', port: 47801 });
    assert.strictEqual(invites, 1, name + ': invite from the list');
  }

  // A TLS server with the guard: a connection from a source not on the list is closed at once.
  NetAllow.set(['100.82.128.47']);
  let destroyed = false;
  NetAllow.guard({ remoteAddress: '::ffff:192.168.50.66', destroy: () => { destroyed = true; } });
  assert.strictEqual(destroyed, true);
  destroyed = false;
  NetAllow.guard({ remoteAddress: '::ffff:100.82.128.47', destroy: () => { destroyed = true; } });
  assert.strictEqual(destroyed, false);

  // Every listener on 0.0.0.0 that a peer reaches carries the guard.
  const root = path.join(__dirname, '..', '..');
  for (const f of ['windows/server.js', 'mac/server.js', 'windows/mesh/server.js', 'mac/mesh/server.js', 'shared/fx2-engine.js', 'shared/fastfile.js']) {
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    assert(/NetAllow\.guard/.test(src), f + ' has no NetAllow.guard');
  }
  assert(/NetAllow\.ok\(rinfo\.address\)/.test(fs.readFileSync(path.join(root, 'shared/inputlane.js'), 'utf8')), 'input lane unguarded');
  console.log('netallow: ok');
})().catch((e) => { console.error(e); process.exit(1); });
