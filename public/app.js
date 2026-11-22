const $ = selector => document.querySelector(selector);
let state;
let selected;
let working = false;
const needsAttention = alert => ['open', 'needs_review', 'unknown'].includes(alert.status);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function notice(message, error = false) {
  $('#notice').textContent = message;
  $('#notice').className = error ? 'notice error' : 'notice';
}

async function refresh() {
  const response = await fetch('/api/state');
  if (!response.ok) throw new Error('Cannot load local workspace.');
  state = await response.json();
  render();
}

async function act(path, body = {}) {
  if (working) return;
  working = true;
  render();
  try {
    notice('Working…');
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Orchestrator-Token': state.csrf },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    notice(result.message);
    if (path === '/api/import') $('#email-text').value = '';
    await refresh();
  } catch (error) {
    notice(error.message, true);
    await refresh().catch(() => {});
  } finally {
    working = false;
    render();
  }
}

function render() {
  if (!state) return;
  const { alerts, connector } = state;
  $('#total').textContent = alerts.filter(needsAttention).length;
  $('#urgent').textContent = alerts.filter(alert => needsAttention(alert) && ['critical', 'high'].includes(alert.severity)).length;
  $('#requested').textContent = alerts.filter(alert => ['requested', 'uncertain', 'checking'].includes(alert.remediation)).length;
  $('#fixed').textContent = alerts.filter(alert => alert.status === 'fixed').length;
  $('#github-status').textContent = connector.configured ? `${connector.repositories.length} allowlisted repositories` : 'Set server environment variables to connect';
  $('#github-badge').textContent = connector.configured ? 'Configured' : 'Not configured';
  $('#github-badge').className = connector.configured ? 'badge ready' : 'badge';
  $('#sync').disabled = working || !connector.configured;
  $('#email-form button').disabled = working;
  const search = $('#search').value.toLowerCase();
  const status = $('#status').value;
  const filtered = alerts.filter(alert =>
    `${alert.repository} ${alert.package} ${alert.title}`.toLowerCase().includes(search)
    && (!$('#severity').value || alert.severity === $('#severity').value)
    && (!status || (status === 'attention' ? needsAttention(alert) : status === 'reviewed' ? alert.reviewed : alert.status === status)));
  $('#count').textContent = `${filtered.length} alerts`;
  $('#alerts').replaceChildren();
  if (!filtered.length) {
    const empty = element('div', 'empty');
    empty.append(element('span', 'empty-icon', '◇'), element('h3', '', alerts.length ? 'No matching alerts' : 'A calmer inbox starts here.'),
      element('p', '', alerts.length ? 'Try another filter.' : 'Import a security email or connect GitHub. No demo data is mixed with your real alerts.'));
    $('#alerts').append(empty);
  }
  for (const alert of filtered) {
    const card = element('article', 'alert-card');
    const badges = element('div', 'alert-meta');
    badges.append(element('span', `badge severity-${alert.severity}`, alert.severity),
      element('span', 'subtle', alert.repository),
      element('span', 'badge', alert.source === 'email' ? 'Email · unverified' : 'GitHub · verified'));
    const title = element('h3', '', alert.title);
    const detail = element('p', 'subtle', `${alert.package} · ${alert.ecosystem} · ${alert.status.replaceAll('_', ' ')}${alert.reviewed ? ' · reviewed locally' : ''}`);
    const actions = element('div', 'alert-actions');
    const plan = element('button', 'secondary', 'View plan ↗');
    plan.onclick = () => openPlan(alert.id);
    const review = element('button', 'quiet', alert.reviewed ? 'Undo review' : 'Mark reviewed');
    review.disabled = working;
    review.onclick = () => act('/api/review', { id: alert.id });
    actions.append(plan, review);
    if (alert.url) {
      const link = element('a', 'quiet', 'Open GitHub ↗');
      // Only canonical alert links are navigable, including after local storage is restored.
      if (/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/security\/dependabot\/\d+$/.test(alert.url)) {
        link.href = alert.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        actions.append(link);
      }
    }
    if (alert.remediation) actions.append(element('span', 'badge', `Fix ${alert.remediation}`));
    card.append(badges, title, detail, actions);
    $('#alerts').append(card);
  }
  updateApproval();
}

function openPlan(id) {
  selected = id;
  const alert = state.alerts.find(item => item.id === id);
  $('#plan-title').textContent = alert.title;
  $('#plan-description').textContent = `${alert.repository} · ${alert.severity} · ${alert.source === 'email' ? 'Unverified email: sync GitHub before requesting a fix.' : 'Verified GitHub alert'}`;
  $('#plan-steps').replaceChildren(...alert.plan.map(step => element('li', '', step)));
  $('#approve').checked = false;
  const connector = state.connector;
  $('#workflow-description').textContent = connector.canRemediate
    ? `Workflow: ${connector.workflow} · ref: ${connector.ref}. Only use workflows you have reviewed and trust.`
    : 'Fix requests are unavailable until GITHUB_REMEDIATION_WORKFLOW and GITHUB_REMEDIATION_REF are configured on the server.';
  updateApproval();
  $('#plan-dialog').showModal();
}

function updateApproval() {
  const alert = state?.alerts.find(item => item.id === selected);
  const eligible = alert?.source === 'github' && alert.status === 'open' && !alert.remediation
    && state.connector.canRemediate && state.connector.repositories.includes(alert.repository);
  $('#approve').disabled = !eligible || working;
  $('#dispatch').disabled = !eligible || working || !$('#approve').checked;
}

$('#sync').onclick = () => act('/api/sync');
$('#email-form').onsubmit = event => {
  event.preventDefault();
  act('/api/import', { text: $('#email-text').value });
};
for (const selector of ['#search', '#severity', '#status']) $(selector).addEventListener('input', render);
$('#approve').onchange = updateApproval;
$('#dispatch').onclick = async () => {
  const id = selected;
  $('#plan-dialog').close();
  await act('/api/remediate', { id, approved: $('#approve').checked });
};
refresh().catch(error => notice(error.message, true));
