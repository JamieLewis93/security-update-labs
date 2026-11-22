import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration, importEmail, normalizeAlert, remediationPlan, Store, GitHub } from '../orchestrator.js';
import { createApp } from '../server.js';

const repository = 'team/project';
const config = { repositories: [repository], token: 'test-only-placeholder', workflow: 'remediate.yml', ref: 'main' };
const rawAlert = (number = 12, state = 'open') => ({
  number, state,
  security_advisory: { summary: 'Prototype pollution' },
  security_vulnerability: { severity: 'high', first_patched_version: { identifier: '2.0.1' } },
  dependency: { package: { name: 'example-package', ecosystem: 'npm' } },
});
const response = (body, status = 200) => new Response(status === 204 ? null : JSON.stringify(body), { status });
const seededStore = () => {
  const store = new Store();
  store.update(normalizeAlert(repository, rawAlert()));
  return store;
};
const id = `github:${repository}:12`;

test('configuration validates allowlisted repositories and workflow filenames', () => {
  assert.deepEqual(configuration({ GITHUB_REPOSITORIES: 'team/project, team/project,other/repo' }).repositories,
    ['team/project', 'other/repo']);
  assert.throws(() => configuration({ GITHUB_REPOSITORIES: '../private?token=yes' }));
  assert.throws(() => configuration({ GITHUB_REMEDIATION_WORKFLOW: '../unsafe.yml' }));
});

test('imports email links once, identifies severity, and does not store the raw body', () => {
  const text = `High severity update\nhttps://github.com/team/project/security/dependabot/12\nhttps://github.com/team/project/security/dependabot/12\nPrivate details`;
  const alerts = importEmail(text);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].severity, 'high');
  assert.equal(alerts[0].source, 'email');
  assert.equal(alerts[0].status, 'needs_review');
  assert.equal(JSON.stringify(alerts).includes('Private details'), false);
  const store = new Store();
  store.import(text);
  store.import(text);
  assert.equal(store.list().length, 1);
});

test('imports multiple alert references and deduplicates case-insensitive repository names', () => {
  const store = new Store();
  store.import('https://github.com/Team/Project/security/dependabot/12\nhttps://github.com/team/project/security/dependabot/13');
  store.import('https://github.com/team/project/security/dependabot/12');
  assert.equal(store.list().length, 2);
});

test('unlinked emails stay unverified; hostile links cannot become external destinations', () => {
  const alerts = importEmail('<img src=x onerror=alert(1)>\nhttps://github.com.evil.invalid/team/project/security/dependabot/12');
  assert.equal(alerts[0].url, null);
  assert.equal(alerts[0].source, 'email');
  assert.equal(alerts[0].severity, 'unknown');
  assert.throws(() => importEmail(' '));
  assert.throws(() => importEmail('a'.repeat(50001)));
  assert.throws(() => importEmail('https://github.com/team/project/security/dependabot/9999999999999999999999'));
});

test('normalizes alert links instead of trusting upstream URLs and provides a transparent plan', () => {
  const alert = normalizeAlert(repository, { ...rawAlert(), html_url: 'https://evil.invalid', state: 'unexpected' });
  assert.equal(alert.url, 'https://github.com/team/project/security/dependabot/12');
  assert.equal(alert.status, 'unknown');
  assert.ok(remediationPlan(alert).some(step => step.includes('2.0.1')));
  assert.ok(remediationPlan(alert).some(step => step.includes('No automatic merging')));
  assert.throws(() => normalizeAlert(repository, rawAlert(-1)));
});

test('sorts alerts by severity without marking unknown severities safe', () => {
  const store = new Store();
  for (const [number, severity] of [[1, 'low'], [2, 'critical'], [3, 'invalid']]) {
    const alert = rawAlert(number);
    alert.security_vulnerability.severity = severity;
    store.update(normalizeAlert(repository, alert));
  }
  assert.deepEqual(store.list().map(alert => alert.severity), ['critical', 'low', 'unknown']);
});

test('local persistence survives restart and has private file permissions', () => {
  const directory = mkdtempSync(join(tmpdir(), 'defence-desk-'));
  let store;
  try {
    store = new Store(directory);
    store.import('High alert\nhttps://github.com/team/project/security/dependabot/12');
    assert.throws(() => new Store(directory), /Workspace locked/);
    store.close();
    store = new Store(directory);
    assert.equal(store.list().length, 1);
    assert.equal(statSync(join(directory, 'alerts.json')).mode & 0o777, 0o600);
    assert.equal(statSync(directory).mode & 0o777, 0o700);
    assert.equal(readFileSync(join(directory, 'alerts.json'), 'utf8').includes(config.token), false);
  } finally {
    store?.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('GitHub sync paginates, upgrades unverified email references and preserves local review', async () => {
  const store = new Store();
  store.import('https://github.com/team/project/security/dependabot/12');
  store.alerts.get(id).reviewed = true;
  let saves = 0;
  store.save = () => saves++;
  const calls = [];
  const github = new GitHub(config, async (url, options) => {
    calls.push({ url, options });
    return response(calls.length === 1 ? Array.from({ length: 100 }, (_, i) => rawAlert(i + 1)) : [rawAlert(101)]);
  });
  assert.equal(await github.sync(store), 101);
  assert.equal(store.alerts.get(id).source, 'github');
  assert.equal(store.alerts.get(id).reviewed, true);
  assert.equal(saves, 1);
  assert.match(calls[1].url, /page=2$/);
  assert.equal(calls[0].options.redirect, 'error');
});

test('partial sync failure leaves the previous workspace intact', async () => {
  const store = seededStore();
  const github = new GitHub({ ...config, repositories: [repository, 'other/repo'] }, async url =>
    url.includes('/other/') ? response({}, 403) : response([rawAlert(13)]));
  await assert.rejects(github.sync(store), /HTTP 403/);
  assert.deepEqual(store.list().map(alert => alert.number), [12]);
});

test('failed sync persistence restores the prior in-memory snapshot', async () => {
  const store = seededStore();
  store.save = () => { throw new Error('Disk full'); };
  const github = new GitHub(config, async () => response([rawAlert(13)]));
  await assert.rejects(github.sync(store), /Disk full/);
  assert.deepEqual(store.list().map(alert => alert.number), [12]);
});

test('remediation refuses missing approval, unverified emails, closed alerts and unconfigured workflows', async () => {
  const github = new GitHub(config, () => assert.fail('must not call GitHub'));
  const store = seededStore();
  await assert.rejects(github.remediate(store, id, false), /approval/);
  store.alerts.get(id).source = 'email';
  await assert.rejects(github.remediate(store, id, true), /verified/);
  store.update(normalizeAlert(repository, rawAlert(12, 'fixed')));
  await assert.rejects(github.remediate(store, id, true), /open/);
  const unconfigured = new GitHub({ ...config, workflow: '' });
  await assert.rejects(unconfigured.remediate(seededStore(), id, true), /Configure/);
});

test('remediation refuses repositories outside the allowlist', async () => {
  const github = new GitHub({ ...config, repositories: [] }, () => assert.fail('must not call GitHub'));
  await assert.rejects(github.remediate(seededStore(), id, true), /GITHUB_REPOSITORIES/);
});

test('approved remediation rechecks the live alert and dispatches only the configured workflow', async () => {
  const calls = [];
  const github = new GitHub(config, async (url, options) => {
    calls.push({ url, options });
    return calls.length === 1 ? response(rawAlert()) : response(null, 204);
  });
  const store = seededStore();
  await github.remediate(store, id, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[0].url.endsWith('/dependabot/alerts/12'));
  assert.ok(calls[1].url.endsWith('/actions/workflows/remediate.yml/dispatches'));
  assert.deepEqual(JSON.parse(calls[1].options.body), { ref: 'main', inputs: { alert_number: '12' } });
  assert.equal(store.alerts.get(id).remediation, 'requested');
  assert.equal(store.alerts.get(id).status, 'open');
  await assert.rejects(github.remediate(store, id, true), /Already requested/);
});

test('no workflow is dispatched when the live alert is fixed', async () => {
  let calls = 0;
  const github = new GitHub(config, async () => {
    calls++;
    return response(rawAlert(12, 'fixed'));
  });
  const store = seededStore();
  await assert.rejects(github.remediate(store, id, true), /no longer open/);
  assert.equal(calls, 1);
  assert.equal(store.alerts.get(id).status, 'fixed');
});

test('uncertain dispatches are persisted and cannot be automatically retried', async () => {
  let calls = 0;
  const github = new GitHub(config, async () => {
    if (++calls === 1) return response(rawAlert());
    throw new Error('network disconnected');
  });
  const store = seededStore();
  await assert.rejects(github.remediate(store, id, true), /may have been accepted/);
  assert.equal(store.alerts.get(id).remediation, 'uncertain');
  store.update(normalizeAlert(repository, rawAlert()));
  assert.equal(store.alerts.get(id).remediation, 'uncertain');
  await assert.rejects(github.remediate(store, id, true), /Already requested/);
  store.update(normalizeAlert(repository, rawAlert(12, 'fixed')));
  assert.equal(store.alerts.get(id).remediation, null);
});

test('definitive dispatch rejection allows a later explicitly approved attempt', async () => {
  let calls = 0;
  const github = new GitHub(config, async () => ++calls === 1 ? response(rawAlert()) : response({}, 422));
  const store = seededStore();
  await assert.rejects(github.remediate(store, id, true), /HTTP 422/);
  assert.equal(store.alerts.get(id).remediation, null);
});

test('server errors and request timeouts cannot prove a dispatch was rejected', async () => {
  for (const status of [408, 500, 502, 503]) {
    let calls = 0;
    const github = new GitHub(config, async () => ++calls === 1 ? response(rawAlert()) : response({}, status));
    const store = seededStore();
    await assert.rejects(github.remediate(store, id, true), new RegExp(`HTTP ${status}`));
    assert.equal(store.alerts.get(id).remediation, 'uncertain');
    await assert.rejects(github.remediate(store, id, true), /Already requested/);
  }
});

test('network failures never expose credentials', async () => {
  const github = new GitHub(config, async () => { throw new Error(config.token); });
  await assert.rejects(github.sync(new Store()), error => !error.message.includes(config.token));
});

test('HTTP app protects writes, denies foreign origins, serves only known assets and hides tokens', async t => {
  // Port zero is used only to find a free test port; the app still validates its actual Host.
  const probe = createApp({ store: new Store(), config, port: 0 });
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const app = createApp({ store: new Store(), config, port });
  await new Promise(resolve => app.listen(port, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.close(resolve)));
  const base = `http://127.0.0.1:${port}`;
  const initial = await fetch(base + '/api/state');
  const state = await initial.json();
  assert.equal(JSON.stringify(state).includes(config.token), false);
  assert.match(initial.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal((await fetch(base + '/.local/alerts.json')).status, 404);
  assert.equal((await fetch(base + '/api/state', { headers: { Origin: 'https://evil.invalid' } })).status, 403);
  const post = (body, headers = {}) => fetch(base + '/api/import', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body,
  });
  assert.equal((await post('{"text":"hello"}')).status, 403);
  const headers = { 'X-Orchestrator-Token': state.csrf };
  assert.equal((await post('null', headers)).status, 400);
  assert.equal((await post('{bad json', headers)).status, 400);
  assert.equal((await post(JSON.stringify({ text: 'High alert' }), headers)).status, 200);
  assert.equal((await (await fetch(base + '/api/state')).json()).alerts.length, 1);
  assert.equal((await fetch(base)).status, 200);
});
