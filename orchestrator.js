import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

const repositoryPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const priorities = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

export function configuration(env = process.env) {
  const repositories = [...new Set((env.GITHUB_REPOSITORIES || '').split(',')
    .map(value => value.trim()).filter(Boolean))];
  if (repositories.some(repo => !repositoryPattern.test(repo))) {
    throw new Error('GITHUB_REPOSITORIES must contain owner/repository names.');
  }
  const workflow = env.GITHUB_REMEDIATION_WORKFLOW || '';
  if (workflow && !/^[A-Za-z0-9_.-]+\.ya?ml$/.test(workflow)) {
    throw new Error('GITHUB_REMEDIATION_WORKFLOW must be a workflow filename.');
  }
  return {
    repositories,
    token: env.GITHUB_TOKEN || '',
    workflow,
    ref: env.GITHUB_REMEDIATION_REF || '',
  };
}

export function importEmail(text) {
  if (typeof text !== 'string' || !text.trim() || text.length > 50000) {
    throw new Error('Paste one security email (up to 50,000 characters).');
  }
  const links = [...text.matchAll(/https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/security\/dependabot\/(\d+)\b/g)];
  const severity = text.match(/\b(critical|high|medium|low)\b/i)?.[1].toLowerCase() || 'unknown';
  const title = text.split(/\r?\n/).map(line => line.trim()).find(Boolean).slice(0, 180);
  const sources = links.length ? links : [null];
  return [...new Map(sources.map(link => {
    const repository = link?.[1] || 'Unclassified email';
    const number = link ? Number(link[2]) : null;
    if (number !== null && (!Number.isSafeInteger(number) || number < 1)) {
      throw new Error('The email contains an invalid alert number.');
    }
    const id = link ? `github:${repository.toLowerCase()}:${number}`
      : `email:${createHash('sha256').update(text.trim()).digest('hex').slice(0, 24)}`;
    return [id, {
      id, repository, number, title, severity, source: 'email', status: 'needs_review',
      package: 'Verify in GitHub', ecosystem: 'Unverified', patchedVersion: null,
      url: link ? `https://github.com/${repository}/security/dependabot/${number}` : null,
      reviewed: false,
    }];
  })).values()];
}

export function normalizeAlert(repository, alert) {
  if (!Number.isSafeInteger(alert.number) || alert.number < 1) {
    throw new Error('GitHub returned an invalid alert number.');
  }
  const vulnerability = alert.security_vulnerability || {};
  const advisory = alert.security_advisory || {};
  return {
    id: `github:${repository.toLowerCase()}:${alert.number}`,
    repository, number: alert.number, source: 'github',
    title: String(advisory.summary || 'Dependabot security alert').slice(0, 300),
    severity: Object.hasOwn(priorities, vulnerability.severity) ? vulnerability.severity : 'unknown',
    package: String(alert.dependency?.package?.name || 'Unknown package'),
    ecosystem: String(alert.dependency?.package?.ecosystem || 'Unknown'),
    patchedVersion: vulnerability.first_patched_version?.identifier || null,
    status: ['open', 'fixed', 'dismissed', 'auto_dismissed'].includes(alert.state) ? alert.state : 'unknown',
    url: `https://github.com/${repository}/security/dependabot/${alert.number}`,
    reviewed: false,
  };
}

export function remediationPlan(alert) {
  return [
    alert.source === 'email'
      ? 'Verify the email against a live GitHub alert before taking action. Imported email text is untrusted.'
      : `Review ${alert.package} in ${alert.repository} (${alert.ecosystem}).`,
    alert.patchedVersion ? `Upgrade to at least ${alert.patchedVersion}; check compatibility and the advisory.`
      : 'Confirm a patched version or mitigation with the maintainer; do not guess a safe version.',
    'Create a branch and pull request using your trusted remediation workflow.',
    'Run tests and security checks; review the diff before merging. No automatic merging.',
    'Verify Dependabot reports the alert fixed. Keep an isolated, tested backup; no tool can guarantee zero risk.',
  ];
}

export class Store {
  constructor(directory) {
    this.directory = directory;
    this.alerts = new Map();
    if (directory) {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      chmodSync(directory, 0o700);
      try {
        const data = JSON.parse(readFileSync(join(directory, 'alerts.json'), 'utf8'));
        for (const alert of data) this.alerts.set(alert.id, alert);
      } catch (error) {
        if (error.code !== 'ENOENT') throw new Error('Cannot read local alert storage; restore or move .local/alerts.json.');
      }
    }
  }

  save() {
    if (!this.directory) return;
    const temporary = join(this.directory, 'alerts.json.tmp');
    writeFileSync(temporary, JSON.stringify([...this.alerts.values()], null, 2), { mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, join(this.directory, 'alerts.json'));
  }

  import(text) {
    const alerts = importEmail(text);
    for (const alert of alerts) {
      if (!this.alerts.has(alert.id)) this.alerts.set(alert.id, alert);
    }
    this.save();
    return alerts.length;
  }

  update(alert) {
    const previous = this.alerts.get(alert.id);
    const pending = ['requested', 'uncertain'].includes(previous?.remediation);
    this.alerts.set(alert.id, {
      ...alert, reviewed: previous?.reviewed || false,
      remediation: alert.status === 'open' && pending ? previous.remediation : null,
    });
    this.save();
  }

  list() {
    return [...this.alerts.values()].sort((a, b) => priorities[b.severity] - priorities[a.severity]
      || a.repository.localeCompare(b.repository));
  }
}

export class GitHub {
  constructor(config, fetcher = fetch) {
    this.config = config;
    this.fetcher = fetcher;
  }

  async request(path, method = 'GET', body) {
    if (!this.config.token) throw new Error('Configure GITHUB_TOKEN on the server first.');
    let response;
    try {
      response = await this.fetcher(`https://api.github.com${path}`, {
        method, redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: {
          Authorization: 'Bearer ' + this.config.token,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'Content-Type': 'application/json',
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      throw new Error('GitHub could not be reached. A dispatch may have been accepted; check Actions before retrying.');
    }
    if (!response.ok) {
      const error = new Error(`GitHub returned HTTP ${response.status}. Check repository access, permissions, rate limits and workflow configuration.`);
      error.definite = true;
      throw error;
    }
    return response.status === 204 ? null : response.json();
  }

  repositoryPath(repository) {
    if (!this.config.repositories.includes(repository)) throw new Error('Repository is not in GITHUB_REPOSITORIES.');
    return `/repos/${repository.split('/').map(encodeURIComponent).join('/')}`;
  }

  async sync(store) {
    if (!this.config.repositories.length) throw new Error('Configure GITHUB_REPOSITORIES first.');
    const fetched = [];
    for (const repository of this.config.repositories) {
      const base = this.repositoryPath(repository);
      for (let page = 1; ; page++) {
        const alerts = await this.request(`${base}/dependabot/alerts?per_page=100&page=${page}`);
        if (!Array.isArray(alerts)) throw new Error('GitHub returned an invalid alert list.');
        fetched.push(...alerts.map(alert => normalizeAlert(repository, alert)));
        if (alerts.length < 100) break;
        if (page >= 100) throw new Error('Sync exceeded 10,000 alerts per repository; narrow the configured repositories.');
      }
    }
    for (const alert of fetched) store.update(alert);
    return fetched.length;
  }

  async remediate(store, id, approved) {
    if (approved !== true) throw new Error('Explicit approval is required.');
    const alert = store.alerts.get(id);
    if (!alert || alert.source !== 'github' || alert.status !== 'open') {
      throw new Error('Only verified, open GitHub alerts can request remediation.');
    }
    if (alert.remediation) throw new Error('Already requested or uncertain. Check GitHub Actions; no automatic retry.');
    if (!this.config.workflow || !this.config.ref) throw new Error('Configure a trusted remediation workflow and ref first.');
    const base = this.repositoryPath(alert.repository);
    alert.remediation = 'checking';
    store.save();
    let dispatching = false;
    try {
      const live = normalizeAlert(alert.repository, await this.request(`${base}/dependabot/alerts/${alert.number}`));
      if (live.number !== alert.number) throw new Error('GitHub returned a different alert.');
      if (live.status !== 'open') {
        store.update(live);
        throw new Error('This alert is no longer open. Sync to refresh the dashboard.');
      }
      alert.remediation = 'uncertain';
      store.save();
      dispatching = true;
      await this.request(`${base}/actions/workflows/${encodeURIComponent(this.config.workflow)}/dispatches`, 'POST', {
        ref: this.config.ref, inputs: { alert_number: String(alert.number) },
      });
      alert.remediation = 'requested';
      store.save();
    } catch (error) {
      if (!dispatching || error.definite) {
        alert.remediation = null;
        store.save();
      }
      throw error;
    }
    return 'Workflow requested, not fixed. Review the pull request and sync to verify resolution.';
  }
}
