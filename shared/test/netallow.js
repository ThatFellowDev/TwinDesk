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

  // A list with nothing valid in it, an empty list or not a list: loopback only, never everyone.
  for (const bad of [['nonsense'], [], {}, 'x', 123]) {
    NetAllow.set(bad);
    assert.strictEqual(NetAllow.ok('100.82.128.47'), false, JSON.stringify(bad));
    assert.strictEqual(NetAllow.ok('127.0.0.1'), true);
  }

  // The file: missing = everyone; unreadable = loopback only.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netallow-'));
  NetAllow.load(path.join(dir, 'none.json'));
  assert.strictEqual(NetAllow.ok('192.168.1.20'), true);
  fs.writeFileSync(path.join(dir, 'bad.json'), '{not json');
  NetAllow.load(path.join(dir, 'bad.json'));
  assert.strictEqual(NetAllow.ok('100.82.128.47'), false);
  for (const [name, body] of [['obj.json', '{"allow":["100.82.128.47"]}'], ['null.json', 'null'], ['big.json', JSON.stringify(Array(20000).fill('100.82.128.47'))]]) {
    fs.writeFileSync(path.join(dir, name), body);
    NetAllow.load(path.join(dir, name));
    assert.strictEqual(NetAllow.ok('100.82.128.47'), false, name);
    assert.strictEqual(NetAllow.ok('127.0.0.1'), true, name);
  }
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

  // Real servers: a connection from a source not on the list is destroyed by the guard they carry.
  NetAllow.set(['100.82.128.47']);
  const fake = (addr) => { const o = { remoteAddress: addr, destroyed: false, destroy() { o.destroyed = true; } }; return o; };
  const guarded = (srv) => srv.listeners('connection').includes(NetAllow.guard);
  {
    const { Engine } = require('../fx2-engine.js');
    const { FastFiles } = require('../fastfile.js');
    const { execFileSync } = require('child_process');
    const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'netallow-tls-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=test',
      '-keyout', path.join(certDir, 'key.pem'), '-out', path.join(certDir, 'cert.pem')], { stdio: 'ignore' });
    const tls = { key: fs.readFileSync(path.join(certDir, 'key.pem'), 'utf8'), cert: fs.readFileSync(path.join(certDir, 'cert.pem'), 'utf8') };
    const e = new Engine(() => {});
    e.handle({ op: 'listen', tls });
    e.handle({ op: 'plain', on: true });
    const ff = new FastFiles({ session: () => null, deliver() {}, send() {} });
    ff.setPlain(true);
    const t0 = Date.now();
    while (!(e.server && e.plainServer && ff.plainServer) && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 5));
    for (const [what, srv] of [['fx2 HTTPS', e.server], ['fx2 plain', e.plainServer], ['fx plain', ff.plainServer]]) assert(guarded(srv), what + ': no guard');
    const out = fake('::ffff:192.168.50.66');
    NetAllow.guard(out);
    assert.strictEqual(out.destroyed, true, 'outside connection kept');
    const inside = fake('::ffff:100.82.128.47');
    NetAllow.guard(inside);
    assert.strictEqual(inside.destroyed, false, 'listed connection closed');
    e.server.close();
    e.plainServer.close();
    ff.setPlain(false);
    fs.rmSync(certDir, { recursive: true, force: true });
  }

  // The session servers (normal and Multi-device) and the off-by-default servers attach the guard to
  // each server they make.
  const root = path.join(__dirname, '..', '..');
  for (const f of ['windows/server.js', 'mac/server.js', 'windows/mesh/server.js', 'mac/mesh/server.js']) {
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    assert(/this\.https = https\.createServer\(this\.tls\);\n\s*this\.https\.requestTimeout = 0;[^\n]*\n\s*this\.https\.on\('connection', NetAllow\.guard\);/.test(src), f + ': session server unguarded');
  }
  for (const [f, n] of [['shared/web/webhub.js', 2], ['shared/foldershare.js', 1], ['shared/rzlive.js', 1]]) {
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    assert.strictEqual((src.match(/\.on\('connection', NetAllow\.guard\)/g) || []).length, n, f + ': guards');
  }
  assert(/net\.createServer\(\(sock\) => \{\n\s*if \(!NetAllow\.ok\(sock\.remoteAddress\)\) return sock\.destroy\(\);/.test(fs.readFileSync(path.join(root, 'shared/airplay/receiver.js'), 'utf8')), 'AirPlay unguarded');
  assert(/_onPacket\(pkt, rinfo\) \{\n\s*if \(!NetAllow\.ok\(rinfo\.address\)\) return;/.test(fs.readFileSync(path.join(root, 'shared/inputlane.js'), 'utf8')), 'input lane unguarded');
  console.log('netallow: ok');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
