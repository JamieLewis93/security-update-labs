import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { configuration, GitHub, Store, remediationPlan } from './orchestrator.js';

const directory = dirname(fileURLToPath(import.meta.url));
const assets = new Map([
  ['/', ['index.html', 'text/html']],
  ['/app.js', ['app.js', 'text/javascript']],
  ['/style.css', ['style.css', 'text/css']],
]);

export function createApp({ config = configuration(), store = new Store(join(directory, '.local')),
  github = new GitHub(config), port = 8787 } = {}) {
  const csrf = randomBytes(32).toString('hex');
  const origin = `http://127.0.0.1:${port}`;
  let busy = false;
  return createServer(async (request, response) => {
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Cache-Control', 'no-store');
    const json = (status, body) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (request.headers.host !== `127.0.0.1:${port}` || (request.headers.origin && request.headers.origin !== origin)) {
      return json(403, { error: 'Use the local dashboard at ' + origin });
    }
    const path = request.url;
    if (request.method === 'GET' && assets.has(path)) {
      const [file, type] = assets.get(path);
      response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
      return response.end(readFileSync(join(directory, 'public', file)));
    }
    if (request.method === 'GET' && path === '/api/state') {
      return json(200, {
        csrf, alerts: store.list().map(alert => ({ ...alert, plan: remediationPlan(alert) })),
        connector: {
          configured: Boolean(config.token && config.repositories.length),
          repositories: config.repositories,
          canRemediate: Boolean(config.token && config.workflow && config.ref),
          workflow: config.workflow, ref: config.ref,
        },
      });
    }
    if (request.method !== 'POST' || !['/api/import', '/api/sync', '/api/review', '/api/remediate'].includes(path)) {
      return json(404, { error: 'Not found.' });
    }
    if (request.headers['x-orchestrator-token'] !== csrf
      || request.headers['content-type'] !== 'application/json') {
      return json(403, { error: 'Use the local dashboard to approve changes.' });
    }
    if (busy) return json(409, { error: 'An operation is in progress. Wait for it to finish.' });
    busy = true;
    try {
      let size = 0;
      const chunks = [];
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 200000) {
          json(413, { error: 'Request too large.' });
          request.resume();
          return;
        }
        chunks.push(chunk);
      }
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
      } catch {
        return json(400, { error: 'Expected a JSON object.' });
      }
      let message;
      if (path === '/api/import') {
        message = `Imported ${store.import(body.text)} alert reference(s). Duplicates are kept only once.`;
      } else if (path === '/api/sync') {
        message = `Synced ${await github.sync(store)} alerts from GitHub.`;
      } else if (path === '/api/review') {
        const alert = store.alerts.get(body.id);
        if (!alert) throw new Error('Alert not found.');
        alert.reviewed = !alert.reviewed;
        store.save();
        message = 'Local review status updated. This does not dismiss or fix the GitHub alert.';
      } else {
        message = await github.remediate(store, body.id, body.approved);
      }
      json(200, { message });
    } catch (error) {
      json(400, { error: error.message });
    } finally {
      busy = false;
    }
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT || 8787);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('PORT must be between 1024 and 65535.');
  const app = createApp({ port });
  app.listen(port, '127.0.0.1', () => console.log(`Defence Desk: http://127.0.0.1:${port}`));
}
