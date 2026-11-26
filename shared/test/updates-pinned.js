// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// The ThatFellowDev pinned build: Updates never asks GitHub, never schedules a check and never installs.
'use strict';

const assert = require('assert');
const { Updates, PINNED } = require('../updates.js');

(async () => {
  assert.strictEqual(PINNED, true);
  let calls = 0;
  const settings = { updates: { auto: true, notified: '', skipped: '', install: true } };
  const u = new Updates({
    current: '3.2.1',
    platform: 'win',
    getSettings: () => settings,
    fetch: async () => { calls++; throw new Error('pinned build fetched'); },
    selfUpdate: { kind: 'win', check: async () => 'win', fits: () => true, download: async () => { calls++; return 'x'; }, install: async () => { calls++; } },
  });
  u.start();
  assert.strictEqual(u.timer, null, 'no periodic check');
  assert.strictEqual(u.first, null, 'no first check');
  await u.check(true);
  u.status.available = true;
  u.status.download = { url: 'https://example.invalid/x.exe', name: 'x.exe' };
  assert.strictEqual(u._installable(), false);
  await u.install();
  await u._autoInstall();
  assert.strictEqual(calls, 0, 'nothing fetched, downloaded or installed');
  console.log('updates-pinned: ok');
})().catch((e) => { console.error(e); process.exit(1); });
