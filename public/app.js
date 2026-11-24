/* Sentinel IR - vanilla JavaScript client; all protected requests use a bearer token. */
const app = document.querySelector('#app');
const toast = document.querySelector('#toast');
const TOKEN_KEY = 'sentinel_session';
const state = { token: localStorage.getItem(TOKEN_KEY) || '', user: null, view: 'incidents', incidents: [], systems: [], users: [], analytics: null, selectedId: null, selectedIncident: null, notifications: [], notificationOpen: false, chatOpen: false, chatMessages: [], socket: null, similarweb: null };
let toastTimer;

const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const dateTime = value => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—';
const shortDate = value => value ? new Date(value).toLocaleDateString([], { month: 'short', day: 'numeric' }) : '';
const initials = name => String(name || 'U').split(/\s+/).slice(0, 2).map(x => x[0]).join('').toUpperCase();
const canInvestigate = () => ['analyst', 'security_admin'].includes(state.user?.role);

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && state.token) signOut(false);
    throw new Error(data.message || 'Request failed. Please try again.');
  }
  return data;
}
function showToast(message, bad = false) {
  toast.textContent = message; toast.classList.toggle('bad', bad); toast.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove('show'), 3400);
}
function roleLabel(role) { return ({ employee: 'Employee', analyst: 'Security analyst', system_admin: 'System admin', security_admin: 'Security admin' })[role] || role; }
function roleNav() {
  const role = state.user.role;
  const items = [];
  if (['employee', 'analyst', 'security_admin'].includes(role)) items.push(['incidents', '◈', role === 'employee' ? 'My reports' : 'Incident queue']);
  if (role === 'security_admin') items.push(['dashboard', '▥', 'Security posture']);
  if (role === 'system_admin') items.push(['systems', '⌘', 'Systems'], ['users', '♙', 'User access']);
  if (role === 'security_admin') items.push(['similarweb', '◉', 'Similarweb research']);
  return items.map(([view, icon, label]) => `<button class="side-link ${state.view === view ? 'active' : ''}" data-view="${view}"><span>${icon}</span>${label}${view === 'incidents' && state.user.role !== 'employee' && state.unreadCritical ? `<b class="nav-count">${state.unreadCritical}</b>` : ''}</button>`).join('');
}

function renderAuth(mode = 'login', error = '') {
  const register = mode === 'register';
  app.innerHTML = `<main class="auth-page"><section class="auth-visual"><div class="brand"><span class="brand-mark">S</span><b>sentinel<span>.</span></b></div><div class="auth-visual-copy"><span class="overline">SECURITY OPERATIONS CENTER</span><h1>See the signal.<br><em>Stop the threat.</em></h1><p>One place to report, investigate, and resolve security incidents.</p></div><div class="auth-grid-art" aria-hidden="true"><div class="orbit o1"></div><div class="orbit o2"></div><div class="orbit o3"></div><div class="core-shield">⌑</div><i class="pulse p1"></i><i class="pulse p2"></i><i class="pulse p3"></i></div><span class="auth-foot">DEFENSE IS A TEAM SPORT · SENTINEL IR</span></section><section class="auth-main"><div class="auth-card"><span class="eyebrow">${register ? 'CREATE EMPLOYEE ACCOUNT' : 'SECURE WORKSPACE'}</span><h2>${register ? 'Join your response team.' : 'Welcome back.'}</h2><p>${register ? 'Create an employee account to report security concerns.' : 'Sign in with your organization account.'}</p><form id="auth-form">${register ? `<label class="field-label">FULL NAME<input name="name" autocomplete="name" minlength="2" maxlength="80" required placeholder="Jordan Lee"></label>` : ''}<label class="field-label">WORK EMAIL<input name="email" type="email" autocomplete="username" required placeholder="name@company.com"></label><label class="field-label">PASSWORD<input name="password" type="password" autocomplete="${register ? 'new-password' : 'current-password'}" minlength="10" required placeholder="At least 10 characters"></label>${register ? `<label class="field-label">DEPARTMENT <span class="optional">OPTIONAL</span><input name="department" maxlength="80" placeholder="e.g. Finance"></label>` : ''}${error ? `<div class="form-error">${esc(error)}</div>` : ''}<button class="button primary full">${register ? 'Create account' : 'Sign in'} <span>→</span></button></form><div class="auth-switch">${register ? 'Already have access?' : 'New employee?'} <button data-auth-mode="${register ? 'login' : 'register'}">${register ? 'Sign in' : 'Create an account'}</button></div><div class="auth-seed-hint"><span>◉</span> Demo analyst, system administrator, and security administrator accounts are configured in the setup guide.</div></div></section></main>`;
  app.querySelector('#auth-form').addEventListener('submit', async event => {
    event.preventDefault(); const button = event.currentTarget.querySelector('button'); button.disabled = true; button.textContent = 'Connecting…';
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      const result = await api(register ? '/api/auth/register' : '/api/auth/login', { method: 'POST', body: JSON.stringify(form) });
      state.token = result.token; state.user = result.user; localStorage.setItem(TOKEN_KEY, result.token); connectSocket(); await initialize();
    } catch (err) { renderAuth(mode, err.message); }
  });
  app.querySelector('[data-auth-mode]').addEventListener('click', () => renderAuth(register ? 'login' : 'register'));
}

function renderShell(content) {
  const unread = state.notifications.filter(item => !item.read).length;
  app.innerHTML = `<div class="app-shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">S</span><b>sentinel<span>.</span></b></div><div class="workspace-tag"><span class="live-dot"></span> SECURITY OPERATIONS</div><nav class="side-nav"><div class="nav-caption">WORKSPACE</div>${roleNav()}</nav><div class="sidebar-bottom"><div class="sidebar-help"><div class="help-icon">?</div><div><b>Need a hand?</b><small>Ask Sentinel Assistant</small></div><button id="open-chat" aria-label="Open assistant">↗</button></div><div class="user-chip"><div class="avatar">${esc(initials(state.user.name))}</div><div class="user-meta"><b>${esc(state.user.name)}</b><small>${esc(roleLabel(state.user.role))}</small></div><button id="sign-out" class="icon-button" title="Sign out">⇥</button></div></div></aside><main class="main-area"><header class="topbar"><div class="crumb"><span>Sentinel IR</span><i>/</i><b>${esc(viewTitle())}</b></div><div class="top-actions"><span class="status-indicator"><i></i> All systems operational</span><button id="notification-button" class="icon-button notification-button" aria-label="Notifications">♧${unread ? `<em>${unread}</em>` : ''}</button><div class="top-avatar">${esc(initials(state.user.name))}</div></div></header><section class="page-content">${content}</section></main></div>${state.notificationOpen ? renderNotificationPanel() : ''}${state.chatOpen ? renderChatPanel() : ''}`;
  bindShell();
}
function viewTitle() { return ({ incidents: 'Incident queue', dashboard: 'Security posture', systems: 'Affected systems', users: 'User access', similarweb: 'Similarweb research' })[state.view] || 'Incident queue'; }
function renderNotificationPanel() {
  return `<div class="drawer-backdrop" id="drawer-backdrop"><aside class="notification-drawer"><div class="drawer-head"><div><span class="eyebrow">ACTIVITY</span><h2>Notifications</h2></div><button class="icon-button" id="close-notifications">×</button></div>${state.notifications.length ? state.notifications.map(item => `<button class="notification-row ${item.read ? '' : 'unread'}" data-notification="${item._id}"><span class="notification-glyph ${item.kind === 'critical' ? 'critical' : ''}">${item.kind === 'critical' ? '!' : '◈'}</span><span><b>${esc(item.title)}</b><small>${esc(item.message)}</small><time>${dateTime(item.createdAt)}</time></span></button>`).join('') : '<div class="empty-note">No notifications yet.</div>'}</aside></div>`;
}
function bindShell() {
  app.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => { state.view = button.dataset.view; state.selectedId = null; state.selectedIncident = null; refreshView(); }));
  app.querySelector('#sign-out')?.addEventListener('click', () => signOut());
  app.querySelector('#open-chat')?.addEventListener('click', () => { state.chatOpen = true; renderCurrent(); });
  app.querySelector('#notification-button')?.addEventListener('click', async () => { try { state.notifications = (await api('/api/notifications')).notifications; } catch {} state.notificationOpen = true; renderCurrent(); });
  app.querySelector('#close-notifications')?.addEventListener('click', () => { state.notificationOpen = false; renderCurrent(); });
  app.querySelector('#drawer-backdrop')?.addEventListener('click', event => { if (event.target.id === 'drawer-backdrop') { state.notificationOpen = false; renderCurrent(); } });
  app.querySelectorAll('[data-notification]').forEach(button => button.addEventListener('click', async () => { await api(`/api/notifications/${button.dataset.notification}/read`, { method: 'PATCH' }); await loadNotifications(); state.notificationOpen = false; renderCurrent(); }));
}
function renderCurrent() {
  if (!state.user) return renderAuth();
  let content = state.view === 'dashboard' ? renderDashboard() : state.view === 'systems' ? renderSystems() : state.view === 'users' ? renderUsers() : state.view === 'similarweb' ? renderSimilarweb() : renderIncidents();
  renderShell(content);
  bindView();
  if (state.chatOpen) bindChat();
}
function bindView() {
  if (state.view === 'incidents') bindIncidents();
  if (state.view === 'dashboard') bindDashboard();
  if (state.view === 'systems') bindSystems();
  if (state.view === 'users') bindUsers();
  if (state.view === 'similarweb') bindSimilarweb();
}
async function refreshView() {
  try {
    if (state.view === 'incidents') { state.incidents = (await api('/api/incidents')).incidents; state.systems = (await api('/api/systems')).systems; }
    if (state.view === 'dashboard') state.analytics = await api('/api/analytics');
    if (state.view === 'systems') state.systems = (await api('/api/systems')).systems;
    if (state.view === 'users') state.users = (await api('/api/users')).users;
    if (state.view === 'similarweb') state.similarweb = await api('/api/similarweb-report');
    if (state.selectedId) { const data = await api(`/api/incidents/${state.selectedId}`); state.selectedIncident = data.incident; }
    renderCurrent();
  } catch (error) { showToast(error.message, true); }
}
async function initialize() {
  state.view = state.user.role === 'system_admin' ? 'systems' : state.user.role === 'security_admin' ? 'dashboard' : 'incidents';
  try {
    if (state.user.role !== 'system_admin') state.incidents = (await api('/api/incidents')).incidents;
    state.systems = (await api('/api/systems')).systems;
    await loadNotifications();
  }
  catch (error) { if (state.token) showToast(error.message, true); }
  renderCurrent();
}
async function loadNotifications() { state.notifications = (await api('/api/notifications')).notifications; }
function signOut(notify = true) {
  state.token = ''; state.user = null; state.socket?.disconnect(); state.socket = null; localStorage.removeItem(TOKEN_KEY);
  if (notify) showToast('You have signed out.'); renderAuth();
}
function connectSocket() {
  state.socket?.disconnect();
  if (!window.io) return;
  state.socket = window.io({ auth: { token: state.token } });
  state.socket.on('notification', async item => { showToast(item.title); try { await loadNotifications(); } catch {} if (state.view === 'incidents') await refreshView(); else renderCurrent(); });
  state.socket.on('incident:updated', async item => { if (!state.selectedId || item.id === state.selectedId || state.view === 'dashboard') await refreshView(); });
}

function renderIncidentRows() {
  if (!state.incidents.length) return `<div class="empty-state"><div class="empty-mark">◈</div><h3>${state.user.role === 'employee' ? 'No reports yet' : 'Your queue is clear'}</h3><p>${state.user.role === 'employee' ? 'Use the report form to tell the security team what you noticed.' : 'New incidents will appear here as they are reported.'}</p></div>`;
  return `<div class="table-wrap"><table><thead><tr><th>INCIDENT</th><th>CATEGORY</th><th>SEVERITY</th><th>STATUS</th><th>ASSIGNEE</th><th>REPORTED</th><th></th></tr></thead><tbody>${state.incidents.map(item => `<tr class="incident-row" data-open-incident="${item._id}"><td><b class="incident-code">${esc(item.incidentCode)}</b><strong>${esc(item.title)}</strong><small>${esc(item.systemSnapshot?.name || 'No system selected')}</small></td><td><span class="category-icon">${categoryIcon(item.category)}</span>${esc(item.category)}</td><td><span class="severity ${item.severity.toLowerCase()}"><i></i>${esc(item.severity)}</span></td><td><span class="status-chip ${item.status.toLowerCase().replace(/\s/g, '-')}">${esc(item.status)}</span></td><td>${esc(item.assignedAnalystName || 'Unassigned')}</td><td>${shortDate(item.reportedAt)}</td><td>↗</td></tr>`).join('')}</tbody></table></div>`;
}
function categoryIcon(category) { return ({ Phishing: '✉', Malware: '⌁', 'Unauthorized Access': '⌑', 'Data Breach': '◉', 'Suspicious Network Activity': '⌁', Other: '◈' })[category] || '◈'; }
function renderReportForm() {
  return `<section class="panel report-panel"><div class="panel-title"><div><span class="eyebrow">EMPLOYEE REPORT</span><h2>Report a suspected incident</h2><p>Share what you observed. The response team will take it from here.</p></div><span class="panel-icon">＋</span></div><form id="report-form" class="report-form"><label class="field-label">WHAT HAPPENED?<input name="title" required minlength="5" maxlength="160" placeholder="e.g. Unexpected login alert on my account"></label><label class="field-label">DESCRIPTION<textarea name="description" required minlength="20" maxlength="8000" rows="4" placeholder="Describe the message, activity, or alert. Include what you clicked or noticed and when."></textarea></label><div class="form-row"><label class="field-label">AFFECTED SYSTEM<select name="systemId"><option value="">Select a system if known</option>${state.systems.map(system => `<option value="${system._id}">${esc(system.name)} · ${esc(system.hostname)}</option>`).join('')}</select></label><label class="field-label">WHEN DID IT HAPPEN?<input type="datetime-local" name="occurredAt"></label></div><label class="field-label upload-field">EVIDENCE FILES <span class="optional">PNG, JPG, PDF, TXT, LOG, CSV, DOCX · UP TO 6 FILES / 10 MB EACH</span><input type="file" name="evidence" multiple accept=".png,.jpg,.jpeg,.pdf,.txt,.log,.csv,.docx"></label><div class="report-footer"><span>◉ You can report an incident even if details are incomplete.</span><button class="button primary">Submit secure report <span>→</span></button></div><div class="form-feedback" id="report-feedback"></div></form></section>`;
}
function renderIncidents() {
  const own = state.user.role === 'employee';
  return `<div class="page-heading"><div><span class="eyebrow">${own ? 'EMPLOYEE WORKSPACE' : 'SECURITY OPERATIONS'}</span><h1>${own ? 'Your reports.' : 'Incident queue.'}</h1><p>${own ? 'Submit a concern and follow the response.' : 'Review, assign, and coordinate active investigations.'}</p></div><div class="heading-tools"><span class="last-updated"><i></i> Live updates enabled</span><button class="button quiet" id="refresh-incidents">↻ Refresh</button></div></div>${own ? renderReportForm() : `<div class="queue-summary"><div><span class="queue-number">${state.incidents.filter(i => !['Resolved','Closed'].includes(i.status)).length}</span><span>active incidents</span></div><div><span class="queue-number critical-text">${state.incidents.filter(i => i.severity === 'Critical' && !['Resolved','Closed'].includes(i.status)).length}</span><span>critical require attention</span></div><div class="queue-tip"><b>Response hygiene</b><span>Preserve evidence and record every action in the incident timeline.</span></div></div>`}<section class="panel queue-panel"><div class="panel-title"><div><span class="eyebrow">${own ? 'REPORT HISTORY' : 'ALL REPORTED INCIDENTS'}</span><h2>${own ? 'Recent reports' : 'Investigation queue'} <span class="sub-count">${state.incidents.length}</span></h2></div><div class="filter-tools"><select id="filter-status"><option value="">All statuses</option>${['Reported','Triaged','Investigating','Contained','Resolved','Closed'].map(x => `<option>${x}</option>`).join('')}</select><select id="filter-severity"><option value="">All severity</option>${['Critical','High','Medium','Low'].map(x => `<option>${x}</option>`).join('')}</select></div></div>${renderIncidentRows()}</section>${state.selectedIncident ? renderIncidentDetail(state.selectedIncident) : ''}`;
}
function renderIncidentDetail(item) {
  const analysts = state.users.filter(user => user.role === 'analyst' && user.active !== false);
  const isSecAdmin = state.user.role === 'security_admin';
  const canWork = canInvestigate();
  const timeline = (item.audit || []).slice().sort((a,b) => new Date(a.createdAt)-new Date(b.createdAt));
  return `<div class="detail-backdrop" id="detail-backdrop"><section class="incident-detail"><div class="detail-head"><div><span class="eyebrow">${esc(item.incidentCode)}</span><h2>${esc(item.title)}</h2><div class="detail-meta"><span class="severity ${item.severity.toLowerCase()}"><i></i>${esc(item.severity)}</span><span class="status-chip ${item.status.toLowerCase().replace(/\s/g, '-')}">${esc(item.status)}</span><span>${esc(item.category)}</span></div></div><button class="icon-button" id="close-detail">×</button></div><div class="detail-body"><div class="detail-main"><section class="detail-section"><h3>Incident summary</h3><p>${esc(item.description)}</p><div class="summary-grid"><div><small>AFFECTED SYSTEM</small><b>${esc(item.systemSnapshot?.name || 'Unspecified')}</b><span>${esc(item.systemSnapshot?.hostname || '')}</span></div><div><small>REPORTED BY</small><b>${esc(item.reporterName)}</b><span>${dateTime(item.reportedAt)}</span></div><div><small>OCCURRED AT</small><b>${dateTime(item.occurredAt)}</b></div><div><small>AI TRIAGE</small><b>${esc(item.category)} · ${Math.round((item.confidence || 0)*100)}%</b><span>${esc(item.severitySource || 'classification')}</span></div></div>${item.duplicateOf ? `<div class="duplicate-banner">⚑ Similar report detected (${Math.round((item.duplicateScore || 0)*100)}% match). Review for correlation.</div>` : ''}</section><section class="detail-section"><h3>Suggested response actions <span class="ai-tag">✦ AI ASSISTED</span></h3><ul class="recommendations">${(item.recommendations || []).map(action => `<li>${esc(action)}</li>`).join('')}</ul></section>${item.attachments?.length ? `<section class="detail-section"><h3>Reported evidence <span class="mini-count">${item.attachments.length}</span></h3><div class="evidence-list">${item.attachments.map(file => evidenceLink(file)).join('')}</div></section>` : ''}${(item.investigationNotes || []).map(note => `<section class="detail-section note-entry"><h3>${esc(note.authorName)} <small>· ${dateTime(note.createdAt)}</small></h3>${note.note ? `<p>${esc(note.note)}</p>` : ''}${note.attachments?.length ? `<div class="evidence-list">${note.attachments.map(file => evidenceLink(file)).join('')}</div>` : ''}</section>`).join('')}${canWork ? `<section class="detail-section"><h3>Add investigation update</h3><form id="investigation-form" data-id="${item._id}"><textarea name="note" rows="3" placeholder="Record observations, containment steps, or handoff details…"></textarea><label class="mini-upload">＋ Attach evidence<input type="file" name="evidence" multiple accept=".png,.jpg,.jpeg,.pdf,.txt,.log,.csv,.docx"></label><button class="button primary small">Save update <span>→</span></button></form></section><section class="detail-section"><h3>Investigation tasks <span class="mini-count">${(item.tasks || []).length}</span></h3><div class="task-list">${(item.tasks || []).map(task => `<div class="task-row"><label><input type="checkbox" data-task="${task._id}" ${task.status === 'Done' ? 'checked' : ''}><span>${esc(task.title)}<small>${esc(task.assignedToName)} · ${esc(task.status)}</small></span></label></div>`).join('') || '<p class="muted">No investigation tasks yet.</p>'}</div><form id="task-form" data-id="${item._id}" class="task-form"><input name="title" required minlength="3" placeholder="Add a response task"><button class="button outline small">＋ Add task</button></form></section>` : ''}<section class="detail-section"><h3>Chronological audit trail</h3><div class="timeline">${timeline.map(event => `<div class="timeline-item"><i></i><div><b>${esc(event.action.replace(/[._]/g, ' '))}</b><small>${esc(event.actorName)} · ${esc(roleLabel(event.actorRole))}</small><p>${auditSummary(event.details)}</p><time>${dateTime(event.createdAt)}</time></div></div>`).join('')}</div></section></div><aside class="detail-rail"><div class="rail-section"><small>STATUS</small>${canWork ? `<select id="edit-status" data-id="${item._id}">${['Reported','Triaged','Investigating','Contained','Resolved','Closed'].map(x => `<option ${x === item.status ? 'selected' : ''}>${x}</option>`).join('')}</select>` : `<b>${esc(item.status)}</b>`}</div><div class="rail-section"><small>SEVERITY</small>${canWork ? `<select id="edit-severity" data-id="${item._id}">${['Low','Medium','High','Critical'].map(x => `<option ${x === item.severity ? 'selected' : ''}>${x}</option>`).join('')}</select>` : `<b>${esc(item.severity)}</b>`}</div><div class="rail-section"><small>ASSIGNED ANALYST</small>${isSecAdmin ? `<select id="edit-assignee" data-id="${item._id}"><option value="">Unassigned</option>${analysts.map(user => `<option value="${user.id}" ${item.assignedAnalystId?.toString() === user.id ? 'selected' : ''}>${esc(user.name)}</option>`).join('')}</select>` : `<b>${esc(item.assignedAnalystName || 'Unassigned')}</b>`}</div><div class="rail-section"><small>ATTACHMENTS</small><b>${(item.attachments || []).length + (item.investigationNotes || []).reduce((sum,n)=>sum+(n.attachments||[]).length,0)} files</b></div><div class="rail-section"><small>LAST UPDATED</small><b>${dateTime(item.updatedAt)}</b></div><div class="rail-footer">Incident changes are written to the audit trail.</div></aside></div></section></div>`;
}
function evidenceLink(file) { return `<a class="evidence-file" href="/api/files/${encodeURIComponent(file.storageName)}" data-evidence-link data-evidence-name="${esc(file.originalName)}" data-evidence-type="${esc(file.mimeType)}"><span>▤</span><span><b>${esc(file.originalName)}</b><small>${(file.size/1024).toFixed(0)} KB · ${esc(file.mimeType)}</small></span>↗</a>`; }
function bindEvidenceLinks() {
  app.querySelectorAll('[data-evidence-link]').forEach(link => link.addEventListener('click', async event => {
    event.preventDefault();
    const mimeType = link.dataset.evidenceType || '';
    const preview = mimeType.startsWith('image/') || mimeType === 'application/pdf';
    const popup = preview ? window.open('about:blank', '_blank') : null;
    if (popup) { popup.opener = null; popup.document.title = 'Opening secure evidence'; popup.document.body.textContent = 'Loading evidence…'; }
    try {
      const response = await fetch(link.href, { headers: { Authorization: `Bearer ${state.token}` } });
      if (!response.ok) {
        const problem = await response.json().catch(() => ({}));
        throw new Error(problem.message || 'Unable to open this evidence file.');
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      if (popup) {
        popup.location.replace(objectUrl);
        setTimeout(() => URL.revokeObjectURL(objectUrl), 120000);
      } else {
        const download = document.createElement('a');
        download.href = objectUrl;
        download.download = link.dataset.evidenceName || 'evidence';
        document.body.append(download); download.click(); download.remove();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
      }
    } catch (error) {
      popup?.close();
      showToast(error.message, true);
    }
  }));
}
function auditSummary(details = {}) { const text = Object.entries(details).map(([key,value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`).join(' · '); return esc(text.slice(0, 360)); }

async function bindIncidents() {
  bindEvidenceLinks();
  app.querySelector('#refresh-incidents')?.addEventListener('click', refreshView);
  app.querySelectorAll('[data-open-incident]').forEach(row => row.addEventListener('click', async () => { state.selectedId = row.dataset.openIncident; try { state.selectedIncident = (await api(`/api/incidents/${state.selectedId}`)).incident; if (state.user.role === 'security_admin') state.users = (await api('/api/users?role=analyst')).users; renderCurrent(); } catch (e) { showToast(e.message, true); } }));
  app.querySelector('#report-form')?.addEventListener('submit', submitReport);
  const statusFilter = app.querySelector('#filter-status'); const severityFilter = app.querySelector('#filter-severity');
  const applyFilter = async () => { const params = new URLSearchParams(); if (statusFilter?.value) params.set('status', statusFilter.value); if (severityFilter?.value) params.set('severity', severityFilter.value); try { state.incidents = (await api(`/api/incidents?${params}`)).incidents; renderCurrent(); } catch(e) { showToast(e.message,true); } };
  statusFilter?.addEventListener('change', applyFilter); severityFilter?.addEventListener('change', applyFilter);
  app.querySelector('#close-detail')?.addEventListener('click', () => { state.selectedId = null; state.selectedIncident = null; renderCurrent(); });
  app.querySelector('#detail-backdrop')?.addEventListener('click', event => { if (event.target.id === 'detail-backdrop') { state.selectedId = null; state.selectedIncident = null; renderCurrent(); } });
  for (const field of ['status','severity','assignee']) app.querySelector(`#edit-${field}`)?.addEventListener('change', async event => {
    const body = field === 'assignee' ? { assignedAnalystId: event.target.value || null } : { [field]: event.target.value };
    try { state.selectedIncident = (await api(`/api/incidents/${event.target.dataset.id}`, { method: 'PATCH', body: JSON.stringify(body) })).incident; state.incidents = (await api('/api/incidents')).incidents; showToast('Incident updated and audited.'); renderCurrent(); } catch (e) { showToast(e.message,true); }
  });
  app.querySelector('#investigation-form')?.addEventListener('submit', submitInvestigation);
  app.querySelector('#task-form')?.addEventListener('submit', submitTask);
  app.querySelectorAll('[data-task]').forEach(input => input.addEventListener('change', async () => {
    const status = input.checked ? 'Done' : 'Open';
    try { const result = await api(`/api/incidents/${app.querySelector('#task-form').dataset.id}/tasks/${input.dataset.task}`, { method: 'PATCH', body: JSON.stringify({ status }) }); state.selectedIncident = result.incident; showToast('Task updated.'); renderCurrent(); } catch(e) { showToast(e.message,true); }
  }));
}
async function submitReport(event) {
  event.preventDefault(); const form = event.currentTarget; const fd = new FormData(form); const fileInput = form.querySelector('[name=evidence]');
  if (!fd.get('occurredAt')) fd.set('occurredAt', new Date().toISOString());
  const feedback = form.querySelector('#report-feedback'); feedback.textContent = 'Submitting report and running incident triage…';
  try {
    const result = await api('/api/incidents', { method: 'POST', body: fd });
    form.reset(); feedback.innerHTML = `Incident <b>${esc(result.incident.incidentCode)}</b> reported · ${esc(result.incident.category)} · <span class="severity ${result.incident.severity.toLowerCase()}">${esc(result.incident.severity)}</span>${result.duplicate ? `<br>Possible duplicate of ${esc(result.duplicate.incidentCode)} (${Math.round(result.duplicate.similarity*100)}% similarity).` : ''}`;
    showToast('Incident submitted. The response team was alerted.'); state.incidents = (await api('/api/incidents')).incidents;
  } catch (error) { feedback.textContent = error.message; showToast(error.message,true); }
}
async function submitInvestigation(event) {
  event.preventDefault(); const form = event.currentTarget; const fd = new FormData(form);
  try { const result = await api(`/api/incidents/${form.dataset.id}/investigation`, { method: 'POST', body: fd }); state.selectedIncident = result.incident; state.incidents = (await api('/api/incidents')).incidents; showToast('Investigation update saved.'); renderCurrent(); }
  catch(error) { showToast(error.message,true); }
}
async function submitTask(event) {
  event.preventDefault(); const form = event.currentTarget;
  try { const result = await api(`/api/incidents/${form.dataset.id}/tasks`, { method: 'POST', body: JSON.stringify({ title: new FormData(form).get('title') }) }); state.selectedIncident = result.incident; showToast('Investigation task assigned.'); renderCurrent(); }
  catch(error) { showToast(error.message,true); }
}

function barRows(values, total = 0, color = 'blue') {
  const entries = Object.entries(values || {}).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) return '<div class="chart-empty">No incident data yet.</div>';
  return entries.map(([label,value]) => `<div class="bar-row"><div><span>${esc(label)}</span><b>${value}</b></div><div class="bar-track"><i class="${color}" style="width:${Math.max(5,total ? value/total*100 : 0)}%"></i></div></div>`).join('');
}
function renderTrend(trend = []) {
  const max = Math.max(1,...trend.map(x=>x.count)); const width=600,height=140,pad=12;
  const points=trend.map((x,i)=>`${pad+i*(width-2*pad)/Math.max(1,trend.length-1)},${height-pad-(x.count/max)*(height-2*pad)}`).join(' ');
  const circles=trend.map((x,i)=>`<circle cx="${pad+i*(width-2*pad)/Math.max(1,trend.length-1)}" cy="${height-pad-(x.count/max)*(height-2*pad)}" r="3"/>`).join('');
  return `<svg class="trend-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none"><defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#58a6ad" stop-opacity=".25"/><stop offset="1" stop-color="#58a6ad" stop-opacity="0"/></linearGradient></defs><polygon points="${pad},${height-pad} ${points} ${width-pad},${height-pad}" fill="url(#trendFill)"/><polyline points="${points}" fill="none" stroke="#25818b" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>${circles}</svg><div class="trend-labels"><span>${shortDate(trend[0]?.date)}</span><span>Last 14 days</span><span>${shortDate(trend.at(-1)?.date)}</span></div>`;
}
function renderDashboard() {
  const a = state.analytics || {}; const critical = a.critical || 0;
  return `<div class="page-heading"><div><span class="eyebrow">SECURITY OPERATIONS CENTER</span><h1>Security posture.</h1><p>Incident activity, analyst workload, and response performance.</p></div><button class="button quiet" id="refresh-dashboard">↻ Refresh metrics</button></div><div class="kpi-grid"><article class="kpi-card"><div class="kpi-top"><span>Total incidents</span><i>◈</i></div><strong>${a.total ?? '—'}</strong><small>all recorded time</small></article><article class="kpi-card"><div class="kpi-top"><span>Active incidents</span><i>⌁</i></div><strong>${a.open ?? '—'}</strong><small>not resolved or closed</small></article><article class="kpi-card ${critical ? 'kpi-alert' : ''}"><div class="kpi-top"><span>Critical active</span><i>!</i></div><strong>${critical}</strong><small>${critical ? 'escalation triggered' : 'no critical incidents'}</small></article><article class="kpi-card"><div class="kpi-top"><span>Mean first response</span><i>◷</i></div><strong>${a.meanResponseMinutes === null || a.meanResponseMinutes === undefined ? '—' : `${a.meanResponseMinutes}<small class="unit"> min</small>`}</strong><small>from report to first triage</small></article><article class="kpi-card"><div class="kpi-top"><span>Mean resolution</span><i>✓</i></div><strong>${a.meanResolutionMinutes === null || a.meanResolutionMinutes === undefined ? '—' : `${a.meanResolutionMinutes}<small class="unit"> min</small>`}</strong><small>from report to resolution</small></article></div><div class="dashboard-grid"><section class="panel chart-panel trend-panel"><div class="panel-title"><div><span class="eyebrow">HISTORICAL ACTIVITY</span><h2>Incident trend <small>14 days</small></h2></div></div>${renderTrend(a.trend)}</section><section class="panel chart-panel"><div class="panel-title"><div><span class="eyebrow">DISTRIBUTION</span><h2>Severity</h2></div></div><div class="bars">${barRows(a.severities,a.total,'severity-bar')}</div></section><section class="panel chart-panel"><div class="panel-title"><div><span class="eyebrow">ATTACK SURFACE</span><h2>Incident categories</h2></div></div><div class="bars">${barRows(a.categories,a.total,'teal')}</div></section><section class="panel chart-panel"><div class="panel-title"><div><span class="eyebrow">AFFECTED ASSETS</span><h2>Systems</h2></div></div><div class="bars">${barRows(a.systems,a.total,'blue')}</div></section><section class="panel chart-panel"><div class="panel-title"><div><span class="eyebrow">TEAM CAPACITY</span><h2>Analyst workload</h2></div></div><div class="bars">${barRows(Object.fromEntries((a.workload||[]).map(item=>[item.name,item.assigned])),Math.max(1,...(a.workload||[]).map(i=>i.assigned)),'orange')}</div></section></div>`;
}
function bindDashboard() { app.querySelector('#refresh-dashboard')?.addEventListener('click', async () => { try { state.analytics = await api('/api/analytics'); renderCurrent(); showToast('Dashboard refreshed.'); } catch(e) { showToast(e.message,true); } }); }

function renderSystems() {
  const editable = state.user.role === 'system_admin';
  return `<div class="page-heading"><div><span class="eyebrow">ASSET INVENTORY</span><h1>Affected systems.</h1><p>Monitored services and endpoints that may be involved in incidents.</p></div><button class="button quiet" id="refresh-systems">↻ Refresh</button></div>${editable ? `<section class="panel add-system-panel"><div class="panel-title"><div><span class="eyebrow">SYSTEM ADMINISTRATION</span><h2>Register a monitored system</h2></div></div><form id="system-form" class="inline-form"><input name="name" required placeholder="System name"><input name="hostname" required placeholder="Hostname or asset group"><input name="type" placeholder="Type"><input name="environment" placeholder="Environment"><input name="owner" placeholder="Owner team"><select name="criticality"><option>Medium</option><option>Low</option><option>High</option><option>Critical</option></select><button class="button primary">Add system <span>→</span></button></form></section>` : ''}<section class="systems-grid">${state.systems.map(system => `<article class="system-card"><div class="system-icon">⌘</div><div class="system-main"><div class="system-card-head"><h3>${esc(system.name)}</h3><span class="status-chip ${system.status === 'Monitored' ? 'contained' : ''}">${esc(system.status)}</span></div><p>${esc(system.hostname)} · ${esc(system.type)}</p><div class="system-card-meta"><span>${esc(system.environment)}</span><span>Owner: ${esc(system.owner || 'Unassigned')}</span></div></div><div class="system-criticality"><small>CRITICALITY</small><b class="severity ${String(system.criticality).toLowerCase()}"><i></i>${esc(system.criticality)}</b><small>Heartbeat ${dateTime(system.lastHeartbeatAt)}</small>${editable ? `<select class="system-status-select" data-system-status="${system._id}" aria-label="Change system monitoring status"><option ${system.status==='Monitored'?'selected':''}>Monitored</option><option ${system.status==='Degraded'?'selected':''}>Degraded</option><option ${system.status==='Isolated'?'selected':''}>Isolated</option></select>` : ''}</div></article>`).join('') || '<div class="empty-state">No monitored systems registered.</div>'}</section>`;
}
function bindSystems() {
  app.querySelector('#refresh-systems')?.addEventListener('click', refreshView);
  app.querySelector('#system-form')?.addEventListener('submit', async event => { event.preventDefault(); const body = Object.fromEntries(new FormData(event.currentTarget)); try { await api('/api/systems',{method:'POST',body:JSON.stringify(body)}); state.systems=(await api('/api/systems')).systems; showToast('System registered.'); renderCurrent(); } catch(e){ showToast(e.message,true); } });
  app.querySelectorAll('[data-system-status]').forEach(select=>select.addEventListener('change',async()=>{try{await api(`/api/systems/${select.dataset.systemStatus}`,{method:'PATCH',body:JSON.stringify({status:select.value})});state.systems=(await api('/api/systems')).systems;showToast('System status updated and audited.');renderCurrent();}catch(e){showToast(e.message,true);}}));
}

function renderUsers() {
  const canAssignRoles = state.user.role === 'system_admin';
  return `<div class="page-heading"><div><span class="eyebrow">ACCESS CONTROL</span><h1>People & permissions.</h1><p>Manage active accounts and least-privilege role access.</p></div><button class="button quiet" id="refresh-users">↻ Refresh users</button></div><section class="panel user-panel"><div class="panel-title"><div><span class="eyebrow">ORGANIZATION USERS</span><h2>${state.users.length} accounts</h2></div><span class="rbac-note">◉ Role changes and account changes are audited.</span></div><div class="table-wrap"><table><thead><tr><th>USER</th><th>EMAIL</th><th>ROLE</th><th>DEPARTMENT</th><th>LAST SIGN-IN</th><th>ACCESS</th></tr></thead><tbody>${state.users.map(user=>`<tr><td><div class="person-cell"><span class="avatar small-avatar">${esc(initials(user.name))}</span><b>${esc(user.name)}</b></div></td><td>${esc(user.email)}</td><td>${canAssignRoles ? `<select class="user-role-select" data-user-role="${user.id}" ${user.id===state.user.id?'disabled':''}>${['employee','analyst','system_admin','security_admin'].map(role=>`<option value="${role}" ${role===user.role?'selected':''}>${esc(roleLabel(role))}</option>`).join('')}</select>` : `<span class="role-pill">${esc(roleLabel(user.role))}</span>`}</td><td>${esc(user.department || '—')}</td><td>${dateTime(user.lastLoginAt)}</td><td><button class="access-toggle ${user.active===false?'disabled':''}" data-user-active="${user.id}" ${user.id===state.user.id?'disabled':''}>${user.active===false?'Disabled':'Active'}</button></td></tr>`).join('')}</tbody></table></div></section>`;
}
function bindUsers() {
  app.querySelector('#refresh-users')?.addEventListener('click', refreshView);
  app.querySelectorAll('[data-user-role]').forEach(select=>select.addEventListener('change',async()=>{try{await api(`/api/users/${select.dataset.userRole}`,{method:'PATCH',body:JSON.stringify({role:select.value})});showToast('Role changed and recorded in the audit trail.');}catch(e){showToast(e.message,true);}}));
  app.querySelectorAll('[data-user-active]').forEach(button=>button.addEventListener('click',async()=>{try{const current=state.users.find(x=>x.id===button.dataset.userActive);await api(`/api/users/${button.dataset.userActive}`,{method:'PATCH',body:JSON.stringify({active:current.active===false})});state.users=(await api('/api/users')).users;showToast('Account access updated.');renderCurrent();}catch(e){showToast(e.message,true);}}));
}

function renderSimilarweb() {
  const report = state.similarweb || {};
  return `<div class="page-heading"><div><span class="eyebrow">DIGITAL MARKET RESEARCH</span><h1>Similarweb analysis.</h1><p>Research brief for positioning Sentinel IR in the incident response landscape.</p></div><span class="research-stamp">RESEARCH<br>BRIEF · 01</span></div><div class="research-notice"><span>ⓘ</span><div><b>Scope and data note</b><p>${esc(report.note || 'Qualitative market analysis. Similarweb metrics require a public domain and are estimates.')}</p></div></div><div class="research-grid">${(report.dimensions||[]).map(item=>`<article class="research-card"><span class="research-icon">◈</span><span class="eyebrow">DIGITAL INTELLIGENCE</span><h2>${esc(item.label)}</h2><p>${esc(item.features)}</p><div><b>Why it helps</b><p>${esc(item.benefit)}</p></div><a class="research-source" href="${esc(item.source)}" target="_blank" rel="noopener">View Similarweb source ↗</a></article>`).join('')}</div><section class="panel research-method"><span class="eyebrow">RECOMMENDED RESEARCH METHOD</span><h2>How to use Similarweb for this project</h2><ol>${(report.analysisSteps||[]).map(step=>`<li>${esc(step)}</li>`).join('')}</ol><p class="muted">The source brief covers Similarweb product capabilities and possible value to a security-product team. It does not represent a live Similarweb API integration or live traffic measurements of this private app.</p></section><section class="panel report-takeaway"><span class="eyebrow">SENTINEL IR POSITIONING</span><h2>From response tool to security operations workflow.</h2><p>Sentinel IR brings employee reporting, analyst investigation, systems context, auditability, and posture analytics into one response workspace. Similarweb research can help compare public vendors’ online reach and acquisition channels; it does not measure the quality of private incident response operations.</p></section>`;
}
function bindSimilarweb() {}

function renderChatPanel() {
  return `<div class="chat-panel"><div class="chat-head"><div class="assistant-avatar">✦</div><div><b>Sentinel assistant</b><small>Cybersecurity guidance · Groq</small></div><span class="ai-tag">AI</span><button id="close-chat" class="icon-button">×</button></div><div class="chat-messages" id="chat-messages">${state.chatMessages.length ? state.chatMessages.map(item=>`<div class="chat-bubble ${item.role}">${esc(item.content).replace(/\n/g,'<br>')}</div>`).join('') : '<div class="chat-welcome"><span>✦</span><b>How can I help?</b><p>Ask about incident response steps, suspicious messages, or security best practices.</p><small>For active incidents, submit a report and follow your organization’s response procedures.</small></div>'}</div><form class="chat-form" id="chat-form"><input name="message" maxlength="1200" required placeholder="Ask a security question…"><button aria-label="Send">↑</button></form><div class="chat-disclaimer">AI-generated guidance can be wrong. Verify actions with your security team.</div></div>`;
}
function bindChat() {
  app.querySelector('#close-chat')?.addEventListener('click',()=>{state.chatOpen=false;renderCurrent();});
  app.querySelector('#chat-form')?.addEventListener('submit',async event=>{
    event.preventDefault();const form=event.currentTarget;const message=new FormData(form).get('message').trim();if(!message)return;
    state.chatMessages.push({role:'user',content:message});renderCurrent();
    const messages=state.chatMessages.slice(-10);
    try{const result=await api('/api/chat',{method:'POST',body:JSON.stringify({messages})});state.chatMessages.push({role:'assistant',content:result.answer});}
    catch(error){state.chatMessages.push({role:'assistant',content:error.message});}
    renderCurrent();const box=app.querySelector('#chat-messages');if(box)box.scrollTop=box.scrollHeight;
  });
}

async function enablePush() {
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return showToast('Push alerts are not supported in this browser.', true);
    const { publicKey } = await api('/api/push/public-key'); if (!publicKey) return showToast('Push is not configured yet. Add VAPID keys in the server environment.', true);
    const permission = await Notification.requestPermission(); if (permission !== 'granted') return showToast('Notification permission was not granted.', true);
    const registration = await navigator.serviceWorker.register('/sw.js');
    const subscription = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: Uint8Array.from(atob(publicKey.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0)) });
    await api('/api/push/subscribe',{method:'POST',body:JSON.stringify({subscription})});showToast('Push alerts enabled.');
  } catch(error) { showToast(error.message,true); }
}

async function boot() {
  if (!state.token) return renderAuth();
  try { state.user = (await api('/api/auth/me')).user; connectSocket(); await initialize(); }
  catch { state.token='';localStorage.removeItem(TOKEN_KEY);renderAuth(); }
}
boot();
