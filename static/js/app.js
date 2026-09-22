/* app.js — the single-page application.
 *
 * Four views (Dashboard, Analyzer, History, Users) plus an audit log, all
 * driven from one state object. Every piece of server data reaches the DOM
 * through R.el(), which assigns textContent only — see render.js for why
 * that matters in this particular application.
 */
'use strict';

const el = R.el;

const state = {
  user: null,
  permissions: [],
  csrf: '',
  view: 'dashboard',
  report: null,
  file: null,
  history: { offset: 0, limit: 25, total: 0, scope: 'mine' },
  allPermissions: [],
  rolePermissions: {},
  editingUser: null
};

const PERMISSION_INFO = {
  analyze:          ['Run analyses',        'Submit emails for analysis'],
  view_history:     ['View own history',    'See their own past analyses'],
  view_all_history: ['View all history',    "See every user's analyses"],
  delete_analysis:  ['Delete analyses',     'Remove records from history'],
  export:           ['Export reports',      'Download reports as JSON'],
  manage_users:     ['Manage users',        'Create, edit and remove accounts'],
  view_audit:       ['View audit log',      'Read the security event log']
};

function can(permission) { return state.permissions.indexOf(permission) !== -1; }

/* ---------------------------------------------------------------- toasts */

function toast(message, kind) {
  const host = document.getElementById('toasts');
  const node = el('div.toast', { text: message, class: 'toast toast-' + (kind || 'info') });
  host.appendChild(node);
  setTimeout(function () {
    node.style.opacity = '0';
    setTimeout(function () { node.remove(); }, 200);
  }, 4200);
}

/* ------------------------------------------------------------ navigation */

const VIEW_TITLES = {
  dashboard: 'Dashboard', analyzer: 'Analyzer',
  history: 'History', users: 'Users', audit: 'Audit log'
};

function showView(name) {
  state.view = name;
  document.querySelectorAll('.view').forEach(function (node) {
    node.hidden = node.id !== 'view-' + name;
  });
  document.querySelectorAll('.nav-item').forEach(function (node) {
    node.classList.toggle('active', node.dataset.view === name);
  });
  document.getElementById('page-title').textContent = VIEW_TITLES[name] || name;

  if (name === 'dashboard') loadDashboard();
  if (name === 'history') loadHistory();
  if (name === 'users') loadUsers();
  if (name === 'audit') loadAudit();
}

/* ------------------------------------------------------------- dashboard */

async function loadDashboard() {
  const scope = document.getElementById('dash-scope').value || 'mine';
  let data;
  try {
    data = await API.get('/api/dashboard?scope=' + encodeURIComponent(scope));
  } catch (err) { toast(err.message, 'error'); return; }

  const stats = [
    ['Total analysed', data.total, null, 'c-accent'],
    ['Phishing', data.phishing, data.total ? pct(data.phishing, data.total) + ' of all' : null, 'c-critical'],
    ['Suspicious', data.suspicious, data.total ? pct(data.suspicious, data.total) + ' of all' : null, 'c-high'],
    ['Genuine', data.genuine, data.total ? pct(data.genuine, data.total) + ' of all' : null, 'c-safe'],
    ['Average risk', data.avg_score, 'out of 100', ''],
    ['Flagged', data.flagged_pct + '%', 'phishing, spam or suspicious', '']
  ];

  R.mount(document.getElementById('stat-grid'), stats.map(function (row) {
    return el('div.stat', {}, [
      el('div.stat-label', { text: row[0] }),
      el('div.stat-value', { text: String(row[1]), class: 'stat-value ' + row[3] }),
      row[2] ? el('div.stat-sub', { text: row[2] }) : null
    ]);
  }));

  // verdict bars
  const order = ['PHISHING', 'SUSPICIOUS', 'SPAM', 'GENUINE'];
  const max = Math.max.apply(null, order.map(function (v) { return data.verdicts[v] || 0; }).concat([1]));
  R.mount(document.getElementById('verdict-bars'), order.map(function (verdict) {
    const count = data.verdicts[verdict] || 0;
    const fill = el('div.bar-fill');
    fill.style.width = (count / max * 100) + '%';
    fill.style.background = R.VERDICT_COLORS[verdict];
    return el('div.bar-row', {}, [
      el('div.bar-label', { text: verdict.charAt(0) + verdict.slice(1).toLowerCase() }),
      el('div.bar-track', {}, fill),
      el('div.bar-count', { text: String(count) })
    ]);
  }));

  renderTrend(data.trend || {});

  // top signals
  const host = document.getElementById('top-signals');
  if (!data.top_signals || !data.top_signals.length) {
    R.mount(host, R.empty('Nothing yet', 'Findings appear here once you analyse some messages.'));
  } else {
    const top = data.top_signals[0][1] || 1;
    R.mount(host, data.top_signals.map(function (row) {
      const fill = el('div.bar-fill');
      fill.style.width = (row[1] / top * 100) + '%';
      fill.style.background = 'var(--accent)';
      return el('div.signal-rank', {}, [
        el('div.signal-rank-name', { text: row[0], title: row[0] }),
        el('div.bar-track', {}, fill),
        el('div.signal-rank-count', { text: String(row[1]) })
      ]);
    }));
  }

  // recent
  const recentHost = document.getElementById('recent-list');
  if (!data.recent || !data.recent.length) {
    R.mount(recentHost, R.empty('No analyses yet', 'Head to the Analyzer to run your first one.'));
  } else {
    R.mount(recentHost, data.recent.map(function (row) {
      return el('div.signal-rank', { class: 'signal-rank clickable', onClick: function () { openReport(row.id); } }, [
        R.verdictBadge(row.verdict),
        el('div.signal-rank-name', {
          text: row.subject || '(no subject)',
          title: row.subject || ''
        }),
        el('div.signal-rank-count', { text: R.when(row.created_at) })
      ]);
    }));
  }
}

function pct(part, total) { return total ? Math.round(part / total * 100) + '%' : '0%'; }

function renderTrend(trend) {
  const host = document.getElementById('trend-chart');
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    days.push(date.toISOString().slice(0, 10));
  }
  const totals = days.map(function (day) {
    const row = trend[day] || {};
    return Object.keys(row).reduce(function (sum, key) { return sum + row[key]; }, 0);
  });
  const max = Math.max.apply(null, totals.concat([1]));

  if (!totals.some(function (t) { return t > 0; })) {
    R.mount(host, R.empty('No activity in the last 14 days', null));
    return;
  }

  const chart = el('div.trend', {}, days.map(function (day, index) {
    const row = trend[day] || {};
    const column = el('div.trend-col', { title: day + ': ' + totals[index] + ' analysed' });
    ['GENUINE', 'SPAM', 'SUSPICIOUS', 'PHISHING'].forEach(function (verdict) {
      const count = row[verdict] || 0;
      if (!count) return;
      const segment = el('div.trend-seg');
      segment.style.height = (count / max * 88) + 'px';
      segment.style.background = R.VERDICT_COLORS[verdict];
      column.appendChild(segment);
    });
    return column;
  }));

  R.mount(host, [chart, el('div.trend-axis', {}, [
    el('span', { text: days[0].slice(5) }),
    el('span', { text: days[days.length - 1].slice(5) })
  ])]);
}

/* -------------------------------------------------------------- analyzer */

function setupAnalyzer() {
  document.querySelectorAll('.tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
      tab.classList.add('active');
      document.getElementById('tab-paste').hidden = tab.dataset.tab !== 'paste';
      document.getElementById('tab-upload').hidden = tab.dataset.tab !== 'upload';
    });
  });

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone.addEventListener('click', function () { fileInput.click(); });
  dropZone.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
  });
  ['dragenter', 'dragover'].forEach(function (evt) {
    dropZone.addEventListener(evt, function (e) {
      e.preventDefault(); dropZone.classList.add('dragover');
    });
  });
  ['dragleave', 'drop'].forEach(function (evt) {
    dropZone.addEventListener(evt, function (e) {
      e.preventDefault(); dropZone.classList.remove('dragover');
    });
  });
  dropZone.addEventListener('drop', function (e) {
    if (e.dataTransfer.files && e.dataTransfer.files.length) chooseFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', function () {
    if (fileInput.files && fileInput.files.length) chooseFile(fileInput.files[0]);
  });

  document.getElementById('analyze-btn').addEventListener('click', runAnalysis);
  document.getElementById('clear-btn').addEventListener('click', function () {
    document.getElementById('email-input').value = '';
    state.file = null;
    R.clear(document.getElementById('file-chosen'));
    R.clear(document.getElementById('results'));
    document.getElementById('analyze-error').hidden = true;
  });
}

function chooseFile(file) {
  state.file = file;
  R.mount(document.getElementById('file-chosen'), el('div.file-chip', {}, [
    el('span', { text: R.truncate(file.name, 48) }),
    el('span.hint', { text: '(' + Math.ceil(file.size / 1024) + ' KB)' })
  ]));
}

async function runAnalysis() {
  const button = document.getElementById('analyze-btn');
  const errorBox = document.getElementById('analyze-error');
  const isUpload = !document.getElementById('tab-upload').hidden;
  const useLlm = document.getElementById('use-llm').checked;
  const useNetwork = document.getElementById('use-network').checked;

  errorBox.hidden = true;

  if (isUpload && !state.file) { toast('Choose a file first.', 'error'); return; }
  if (!isUpload && !document.getElementById('email-input').value.trim()) {
    toast('Paste an email first.', 'error'); return;
  }

  button.disabled = true;
  R.mount(button, [el('span.spinner'), document.createTextNode(' Analysing…')]);

  try {
    let report;
    if (isUpload) {
      const form = new FormData();
      form.append('file', state.file);
      form.append('use_llm', useLlm ? 'true' : 'false');
      form.append('use_network', useNetwork ? 'true' : 'false');
      report = await API.upload('/api/analyze/upload', form);
    } else {
      report = await API.post('/api/analyze', {
        content: document.getElementById('email-input').value,
        use_llm: useLlm,
        use_network: useNetwork
      });
    }
    state.report = report;
    R.mount(document.getElementById('results'), buildReport(report));
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    R.mount(button, document.createTextNode('Analyse'));
  }
}

/* ---------------------------------------------------------- report render */

function buildReport(report) {
  const nodes = [];

  // ---- headline: gauge + verdict + written assessment ----
  const circumference = 2 * Math.PI * 46;
  const offset = circumference * (1 - report.risk_score / 100);
  const color = R.scoreColor(report.risk_score);

  const gaugeSvg = el('div.gauge', { html:
    '<svg viewBox="0 0 108 108">' +
      '<circle class="gauge-track" cx="54" cy="54" r="46"></circle>' +
      '<circle class="gauge-fill" cx="54" cy="54" r="46" ' +
        'stroke="' + color + '" stroke-dasharray="' + circumference + '" ' +
        'stroke-dashoffset="' + offset + '"></circle>' +
    '</svg>'
  });
  const gaugeText = el('div.gauge-text', {}, [
    el('div.gauge-score', { text: String(report.risk_score) }),
    el('div.gauge-max', { text: 'RISK / 100' })
  ]);
  gaugeText.querySelector('.gauge-score').style.color = color;
  gaugeSvg.appendChild(gaugeText);

  const facts = [
    ['Confidence', report.confidence + '%'],
    ['Sender', report.authenticated_sender ? 'verified (aligned DKIM + DMARC)' : 'not verified'],
    ['Findings', String((report.signals || []).length)],
    // llm_status is 'ok:<provider>' (or 'ok:<provider> (fallback; ...)'), so
    // this is a prefix test. Naming the provider matters when the fallback
    // answered — the report should not imply the primary was healthy.
    ['Analysis', report.llm_status && report.llm_status.indexOf('ok') === 0
       ? 'rules + AI · ' + report.llm_status.slice(3) : 'rules only'],
    ['Time', report.duration_ms + ' ms']
  ];
  if (report.rules_overrode_llm) facts.push(['Override', 'evidence outranked AI']);

  nodes.push(el('div.result-head', {}, [
    gaugeSvg,
    el('div.result-meta', {}, [
      el('div.result-verdict', {}, [
        R.verdictBadge(report.verdict),
        // The theft vectors say WHY this is phishing rather than merely
        // unwanted, which is the question an examiner actually asks.
        ...(report.theft_vectors || []).map(function (v) {
          return R.badge(v.replace(/_/g, ' '), 'critical');
        }),
        report.authenticated_sender ? R.badge('sender verified', 'safe') : null,
        report.divergence === 'llm_only_detection'
          ? R.badge('AI-only detection', 'high') : null,
        report.email && !report.email.headers_present
          ? R.badge('body only', 'medium') : null,
        report.llm_status && report.llm_status.indexOf('error') === 0
          ? R.badge('AI unavailable', 'info') : null
      ]),
      el('div.result-summary', { text: report.summary || '' }),
      el('div.result-facts', {}, facts.map(function (f) {
        return el('span', {}, [el('strong', { text: f[0] + ': ' }), document.createTextNode(f[1])]);
      }))
    ])
  ]));

  // ---- severity tally ----
  const counts = {};
  (report.signals || []).forEach(function (s) { counts[s.severity] = (counts[s.severity] || 0) + 1; });
  const tally = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].filter(function (s) { return counts[s]; });
  if (tally.length) {
    nodes.push(el('div.sev-summary', {}, tally.map(function (severity) {
      return R.badge(counts[severity] + ' ' + severity.toLowerCase(), severity.toLowerCase());
    })));
  }

  // ---- evidence ----
  const evidencePanel = el('div.panel', {}, [el('div.panel-title', { text: 'Evidence' })]);
  if (!report.signals || !report.signals.length) {
    evidencePanel.appendChild(R.empty('No findings',
      'No detection rule matched this message.'));
  } else {
    report.signals.forEach(function (signal) {
      evidencePanel.appendChild(buildEvidence(signal));
    });
  }
  nodes.push(evidencePanel);

  // ---- message details ----
  const email = report.email || {};
  const rows = [
    ['From', email.from_address], ['Display name', email.from_display],
    ['Reply-To', email.reply_to], ['Return-Path', email.return_path],
    ['To', email.to], ['Subject', email.subject], ['Date', email.date],
    ['Message-ID', email.message_id], ['Auth results', email.auth_results],
    ['Routing hops', email.received_chain ? String(email.received_chain.length) : '0']
  ].filter(function (row) { return row[1]; });

  if (rows.length) {
    const list = el('dl.kv');
    rows.forEach(function (row) {
      list.appendChild(el('dt', { text: row[0] }));
      list.appendChild(el('dd', { text: R.truncate(row[1], 240) }));
    });
    nodes.push(el('div.panel', {}, [el('div.panel-title', { text: 'Message details' }), list]));
  }

  // ---- links ----
  if (email.links && email.links.length) {
    const body = el('tbody');
    email.links.slice(0, 60).forEach(function (link) {
      body.appendChild(el('tr', {}, [
        el('td.cell-mono', {}, el('div.cell-truncate', { text: link.url, title: link.url })),
        el('td.cell-mono', { text: link.registered_domain || '—' }),
        el('td', {}, link.display_text
          ? el('div.cell-truncate', { text: link.display_text, title: link.display_text })
          : document.createTextNode('—')),
        el('td', {}, link.is_mismatch ? R.badge('mismatch', 'critical') : document.createTextNode(''))
      ]));
    });
    nodes.push(el('div.panel', {}, [
      el('div.panel-title', { text: 'Links (' + email.links.length + ')' }),
      el('div.table-wrap', {}, el('table', {}, [
        el('thead', {}, el('tr', {}, [
          el('th', { text: 'URL' }), el('th', { text: 'Domain' }),
          el('th', { text: 'Shown as' }), el('th', { text: '' })
        ])), body
      ]))
    ]));
  }

  // ---- attachments ----
  if (email.attachments && email.attachments.length) {
    const body = el('tbody');
    email.attachments.forEach(function (att) {
      body.appendChild(el('tr', {}, [
        el('td', { text: att.filename }),
        el('td.cell-mono', { text: att.content_type || '—' }),
        el('td.cell-num', { text: att.size ? att.size.toLocaleString() + ' B' : '—' }),
        el('td.cell-mono', { text: att.detected_type || 'unidentified' }),
        el('td.cell-mono', { text: att.sha256 ? att.sha256.slice(0, 16) + '…' : '—',
                             title: att.sha256 || '' })
      ]));
    });
    nodes.push(el('div.panel', {}, [
      el('div.panel-title', { text: 'Attachments (' + email.attachments.length + ')' }),
      el('div.table-wrap', {}, el('table', {}, [
        el('thead', {}, el('tr', {}, [
          el('th', { text: 'Filename' }), el('th', { text: 'Declared type' }),
          el('th', { text: 'Size' }), el('th', { text: 'Actual type' }), el('th', { text: 'SHA-256' })
        ])), body
      ]))
    ]));
  }

  // ---- why this is not phishing ----
  // A high score with no theft vector is the pharmacy-spam case. Saying so
  // explicitly is more useful than leaving the analyst to infer it.
  if (!(report.theft_vectors || []).length && report.risk_score >= 25) {
    nodes.push(el('div.panel', {}, [
      el('div.panel-title', { text: 'Why this is not classified as phishing' }),
      el('p.result-summary', { text:
        'No theft vector was found: no credential request to an untrusted destination, ' +
        'no brand impersonation, no payment redirection and no credential-harvesting ' +
        'attachment. The risk score reflects poor sending practice, not an attempt to ' +
        'steal from the recipient — so the label is capped below PHISHING.' })
    ]));
  }

  // ---- score breakdown ----
  const breakdown = report.breakdown || {};
  const components = [
    ['Authentication', breakdown.auth_points], ['Headers', breakdown.header_points],
    ['URLs', breakdown.url_points], ['Content', breakdown.content_points],
    ['Attachments', breakdown.attachment_points]
  ].filter(function (c) { return c[1]; });
  if (components.length) {
    const max = Math.max.apply(null, components.map(function (c) { return c[1]; }).concat([1]));
    nodes.push(el('div.panel', {}, [
      el('div.panel-title', { text: 'Score contribution by category' })
    ].concat(components.map(function (component) {
      const fill = el('div.bar-fill');
      fill.style.width = (component[1] / max * 100) + '%';
      fill.style.background = 'var(--accent)';
      return el('div.bar-row', {}, [
        el('div.bar-label', { text: component[0] }),
        el('div.bar-track', {}, fill),
        el('div.bar-count', { text: String(component[1]) })
      ]);
    })).concat([
      el('p.hint', { text:
        'Points use diminishing returns within each category, so repeated weak findings ' +
        'cannot outweigh a small number of strong ones. Correlated patterns and positive ' +
        'indicators are applied on top and appear in the evidence list.' })
    ])));
  }

  // ---- raw body ----
  if (email.body_text) {
    nodes.push(el('div.panel', {}, [
      el('div.panel-title', { text: 'Message body (text, not rendered)' }),
      el('div.raw-box', { text: R.truncate(email.body_text, 12000) })
    ]));
  }

  if (email.parse_notes && email.parse_notes.length) {
    nodes.push(el('div.alert.alert-info', {}, email.parse_notes.map(function (note) {
      return el('div', { text: note });
    })));
  }

  return nodes;
}

function buildEvidence(signal) {
  const severity = signal.severity || 'INFO';
  const bar = el('div.evidence-bar');
  bar.style.background = R.SEVERITY_COLORS[severity];

  const body = el('div.evidence-body', {}, [
    el('div.evidence-detail', { text: signal.detail || '' }),
    signal.evidence ? el('div.evidence-proof', { text: signal.evidence }) : null
  ]);

  const wrapper = el('div.evidence');
  const head = el('div.evidence-head', {
    role: 'button', tabindex: '0',
    onClick: function () { wrapper.classList.toggle('open'); }
  }, [
    bar,
    el('div.evidence-main', {}, [
      el('div.evidence-title', { text: signal.title || signal.code }),
      el('div.evidence-code', {
        text: signal.code + (signal.weight ? '   +' + signal.weight : '')
      })
    ]),
    R.badge(severity.toLowerCase(), severity.toLowerCase()),
    el('div.evidence-chev', { html: R.chevron })
  ]);
  head.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); wrapper.classList.toggle('open'); }
  });

  wrapper.appendChild(head);
  wrapper.appendChild(body);
  if (severity === 'CRITICAL') wrapper.classList.add('open');
  return wrapper;
}

/* --------------------------------------------------------------- history */

async function loadHistory() {
  const params = new URLSearchParams({
    limit: state.history.limit,
    offset: state.history.offset,
    sort: document.getElementById('hist-sort').value,
    scope: document.getElementById('hist-scope').value || 'mine'
  });
  const verdict = document.getElementById('hist-verdict').value;
  const search = document.getElementById('hist-search').value.trim();
  if (verdict) params.set('verdict', verdict);
  if (search) params.set('search', search);

  let data;
  try { data = await API.get('/api/history?' + params.toString()); }
  catch (err) { toast(err.message, 'error'); return; }

  state.history.total = data.total;
  const tbody = document.getElementById('history-body');
  const emptyHost = document.getElementById('history-empty');
  R.clear(tbody); R.clear(emptyHost);

  if (!data.items.length) {
    emptyHost.appendChild(R.empty(
      search || verdict ? 'No matching analyses' : 'No analyses yet',
      search || verdict ? 'Try a different filter.' : 'Run one from the Analyzer tab.'
    ));
  } else {
    data.items.forEach(function (row) {
      const actions = el('div.gap-8');
      if (can('export')) {
        actions.appendChild(el('a.btn.btn-sm', {
          text: 'JSON', href: '/api/analysis/' + row.id + '/export', download: ''
        }));
      }
      if (can('delete_analysis')) {
        actions.appendChild(el('button.btn.btn-sm.btn-danger', {
          text: 'Delete',
          onClick: function (event) { event.stopPropagation(); deleteAnalysis(row.id); }
        }));
      }
      tbody.appendChild(el('tr.clickable', { onClick: function () { openReport(row.id); } }, [
        el('td', { text: R.when(row.created_at), title: R.exact(row.created_at) }),
        el('td', {}, el('div.cell-truncate', {
          text: row.subject || '(no subject)', title: row.subject || '' })),
        el('td.cell-mono', {}, el('div.cell-truncate', {
          text: row.sender || '—', title: row.sender || '' })),
        el('td', {}, [
          R.verdictBadge(row.verdict),
          // Why it was labelled that way, visible without opening the report.
          ...(row.theft_vectors ? row.theft_vectors.split(',') : []).map(function (v) {
            return R.badge(v.replace(/_/g, ' '), 'critical');
          }),
          row.authenticated ? R.badge('verified', 'safe') : null
        ]),
        el('td.cell-num', {}, R.scorePill(row.risk_score)),
        el('td.cell-num', { text: String(row.signal_count) }),
        el('td', {}, actions)
      ]));
    });
  }

  const from = data.total ? state.history.offset + 1 : 0;
  const to = Math.min(state.history.offset + state.history.limit, data.total);
  document.getElementById('hist-count').textContent =
    data.total ? 'Showing ' + from + '–' + to + ' of ' + data.total : 'No results';
  document.getElementById('hist-prev').disabled = state.history.offset === 0;
  document.getElementById('hist-next').disabled = to >= data.total;
}

async function deleteAnalysis(id) {
  if (!window.confirm('Delete this analysis? This cannot be undone.')) return;
  try {
    await API.del('/api/analysis/' + id);
    toast('Analysis deleted.', 'success');
    loadHistory();
  } catch (err) { toast(err.message, 'error'); }
}

async function openReport(id) {
  try {
    const report = await API.get('/api/analysis/' + id);
    R.mount(document.getElementById('report-modal-body'), buildReport(report));
    document.getElementById('report-modal').hidden = false;
  } catch (err) { toast(err.message, 'error'); }
}

/* ----------------------------------------------------------------- users */

async function loadUsers() {
  let data;
  try { data = await API.get('/api/users'); }
  catch (err) { toast(err.message, 'error'); return; }

  state.allPermissions = data.all_permissions;
  state.rolePermissions = data.roles;

  const tbody = document.getElementById('users-body');
  R.clear(tbody);

  data.users.forEach(function (user) {
    const dot = el('span.dot', { class: 'dot ' + (user.locked ? 'dot-locked' : user.is_active ? 'dot-on' : 'dot-off'),
                                 title: user.locked ? 'Locked' : user.is_active ? 'Active' : 'Disabled' });
    const actions = el('div.gap-8', {}, [
      el('button.btn.btn-sm', { text: 'Edit', onClick: function () { openUserModal(user); } }),
      el('button.btn.btn-sm', { text: 'Reset password', onClick: function () { resetPassword(user); } }),
      user.locked ? el('button.btn.btn-sm', { text: 'Unlock', onClick: function () { unlockUser(user); } }) : null,
      user.id !== state.user.id
        ? el('button.btn.btn-sm.btn-danger', { text: 'Delete', onClick: function () { deleteUser(user); } })
        : null
    ]);

    tbody.appendChild(el('tr', {}, [
      el('td', {}, dot),
      el('td', {}, [
        el('div', { text: user.username }),
        user.must_change_password ? el('div.hint', { text: 'must change password' }) : null
      ]),
      el('td.cell-mono', { text: user.email || '—' }),
      el('td', {}, R.badge(user.role, user.role === 'admin' ? 'critical' : user.role === 'analyst' ? 'low' : 'info')),
      el('td', { text: user.permissions.length + ' granted',
                 title: user.permissions.join(', ') }),
      el('td', { text: user.last_login ? R.when(user.last_login) : 'never',
                 title: R.exact(user.last_login) }),
      el('td', {}, actions)
    ]));
  });
}

function openUserModal(user) {
  state.editingUser = user || null;
  const creating = !user;

  document.getElementById('user-modal-title').textContent = creating ? 'New user' : 'Edit ' + user.username;
  document.getElementById('username-field').hidden = !creating;
  document.getElementById('password-field').hidden = !creating;
  document.getElementById('active-field').hidden = creating;
  document.getElementById('user-error').hidden = true;

  document.getElementById('u-username').value = '';
  document.getElementById('u-password').value = creating ? generatePassword() : '';
  document.getElementById('u-email').value = user ? user.email : '';
  document.getElementById('u-role').value = user ? user.role : 'viewer';
  document.getElementById('u-active').checked = user ? user.is_active : true;

  renderPermissions(user ? user.permissions : state.rolePermissions['viewer'] || []);
  document.getElementById('user-modal').hidden = false;
}

function renderPermissions(granted) {
  const host = document.getElementById('perm-grid');
  R.mount(host, state.allPermissions.map(function (permission) {
    const info = PERMISSION_INFO[permission] || [permission, ''];
    const input = el('input', { type: 'checkbox', value: permission });
    input.checked = granted.indexOf(permission) !== -1;
    return el('label.perm-item', {}, [
      input,
      el('div.perm-text', {}, [
        el('div.perm-name', { text: info[0] }),
        el('div.perm-desc', { text: info[1] })
      ])
    ]);
  }));
}

function selectedPermissions() {
  return Array.prototype.slice
    .call(document.querySelectorAll('#perm-grid input:checked'))
    .map(function (input) { return input.value; });
}

function generatePassword() {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';
  const values = new Uint32Array(18);
  crypto.getRandomValues(values);
  return Array.from(values).map(function (v) { return alphabet[v % alphabet.length]; }).join('');
}

async function saveUser() {
  const errorBox = document.getElementById('user-error');
  errorBox.hidden = true;
  const button = document.getElementById('user-save');
  button.disabled = true;

  try {
    if (state.editingUser) {
      await API.patch('/api/users/' + state.editingUser.id, {
        email: document.getElementById('u-email').value,
        role: document.getElementById('u-role').value,
        permissions: selectedPermissions(),
        is_active: document.getElementById('u-active').checked
      });
      toast('User updated. Their sessions were revoked so the change takes effect now.', 'success');
    } else {
      const password = document.getElementById('u-password').value;
      await API.post('/api/users', {
        username: document.getElementById('u-username').value,
        password: password,
        email: document.getElementById('u-email').value,
        role: document.getElementById('u-role').value,
        permissions: selectedPermissions()
      });
      window.prompt('User created. Copy this initial password — it is not stored in readable form ' +
                    'and cannot be shown again:', password);
    }
    document.getElementById('user-modal').hidden = true;
    loadUsers();
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
  }
}

async function resetPassword(user) {
  const password = generatePassword();
  if (!window.confirm('Reset the password for ' + user.username + '?\n\n' +
                      'Every session they hold will be revoked and they must set a new ' +
                      'password at next sign-in.')) return;
  try {
    await API.post('/api/users/' + user.id + '/password', { new_password: password });
    window.prompt('Password reset. Give this to ' + user.username + ' — it cannot be shown again:', password);
    loadUsers();
  } catch (err) { toast(err.message, 'error'); }
}

async function unlockUser(user) {
  try {
    await API.post('/api/users/' + user.id + '/unlock', {});
    toast(user.username + ' unlocked.', 'success');
    loadUsers();
  } catch (err) { toast(err.message, 'error'); }
}

async function deleteUser(user) {
  if (!window.confirm('Delete ' + user.username + '? This cannot be undone.')) return;
  try {
    await API.del('/api/users/' + user.id);
    toast('User deleted.', 'success');
    loadUsers();
  } catch (err) { toast(err.message, 'error'); }
}

/* ----------------------------------------------------------------- audit */

async function loadAudit() {
  let data;
  try { data = await API.get('/api/audit?limit=200'); }
  catch (err) { toast(err.message, 'error'); return; }

  const severityVariant = { critical: 'critical', error: 'critical', warning: 'high', info: 'info' };
  const tbody = document.getElementById('audit-body');
  R.clear(tbody);

  if (!data.items.length) {
    tbody.appendChild(el('tr', {}, el('td', { colspan: '5' }, R.empty('No events recorded', null))));
    return;
  }
  data.items.forEach(function (row) {
    tbody.appendChild(el('tr', {}, [
      el('td', { text: R.when(row.ts), title: R.exact(row.ts) }),
      el('td', {}, R.badge(row.event, severityVariant[row.severity] || 'info')),
      el('td', { text: row.username || '—' }),
      el('td.cell-mono', { text: row.ip || '—' }),
      el('td', {}, el('div.cell-truncate', { text: row.detail || '', title: row.detail || '' }))
    ]));
  });
}

/* ------------------------------------------------------------- samples */

async function loadSamples() {
  let data;
  try { data = await API.get('/api/samples'); } catch (err) { return; }
  if (!data.samples || !data.samples.length) return;

  const host = document.getElementById('sample-bar');
  R.mount(host, [el('span.hint', { text: 'Try a sample:' })].concat(
    data.samples.map(function (sample) {
      return el('button.btn.btn-sm', {
        text: sample.name,
        onClick: function () {
          document.querySelector('.tab[data-tab="paste"]').click();
          document.getElementById('email-input').value = sample.content;
          toast('Loaded "' + sample.name + '". Press Analyse.', 'info');
        }
      });
    })
  ));
}

/* -------------------------------------------------------------- bootstrap */

document.addEventListener('DOMContentLoaded', async function () {
  let me;
  try { me = await API.get('/api/me'); }
  catch (err) { window.location.href = '/login'; return; }

  state.user = me.user;
  state.permissions = me.user.permissions || [];
  state.csrf = me.csrf_token;

  document.getElementById('user-name').textContent = me.user.username;
  document.getElementById('user-role').textContent = me.user.role;
  document.getElementById('avatar').textContent = me.user.username.slice(0, 2).toUpperCase();

  const badge = document.getElementById('mode-badge');
  badge.textContent = me.llm.mode;
  badge.className = 'badge ' + (me.llm.configured ? 'badge-low' : 'badge-info');
  badge.title = me.llm.configured
    ? 'Primary: ' + me.llm.provider + ' / ' + me.llm.model +
      (me.llm.fallback ? '\nFallback: ' + me.llm.fallback : '\nNo fallback configured.')
    : 'No API key configured — the analyser is running on its deterministic rules engine alone.';

  // Views the user cannot reach are removed, not merely hidden. The server
  // enforces every permission independently; this only keeps the interface
  // honest about what is available.
  document.getElementById('nav-users').hidden = !can('manage_users');
  document.getElementById('nav-audit').hidden = !can('view_audit');
  if (!can('analyze')) {
    document.querySelector('.nav-item[data-view="analyzer"]').hidden = true;
  }
  if (me.can_view_all || can('view_all_history')) {
    document.getElementById('dash-scope').hidden = false;
    document.getElementById('hist-scope-field').hidden = false;
  }

  document.querySelectorAll('.nav-item').forEach(function (item) {
    item.addEventListener('click', function () { showView(item.dataset.view); });
  });

  document.getElementById('logout').addEventListener('click', async function () {
    try { await API.post('/api/logout', {}); } catch (e) { /* leaving anyway */ }
    window.location.href = '/login';
  });

  setupAnalyzer();

  document.getElementById('dash-scope').addEventListener('change', loadDashboard);
  ['hist-verdict', 'hist-sort', 'hist-scope'].forEach(function (id) {
    document.getElementById(id).addEventListener('change', function () {
      state.history.offset = 0; loadHistory();
    });
  });
  let searchTimer;
  document.getElementById('hist-search').addEventListener('input', function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () { state.history.offset = 0; loadHistory(); }, 280);
  });
  document.getElementById('hist-prev').addEventListener('click', function () {
    state.history.offset = Math.max(0, state.history.offset - state.history.limit);
    loadHistory();
  });
  document.getElementById('hist-next').addEventListener('click', function () {
    state.history.offset += state.history.limit;
    loadHistory();
  });

  document.getElementById('new-user-btn').addEventListener('click', function () { openUserModal(null); });
  document.getElementById('user-save').addEventListener('click', saveUser);
  document.getElementById('gen-password').addEventListener('click', function () {
    document.getElementById('u-password').value = generatePassword();
  });
  document.getElementById('u-role').addEventListener('change', function () {
    if (!state.editingUser) renderPermissions(state.rolePermissions[this.value] || []);
  });

  ['user-modal-close', 'user-cancel'].forEach(function (id) {
    document.getElementById(id).addEventListener('click', function () {
      document.getElementById('user-modal').hidden = true;
    });
  });
  document.getElementById('report-modal-close').addEventListener('click', function () {
    document.getElementById('report-modal').hidden = true;
  });
  [['user-modal'], ['report-modal']].forEach(function (pair) {
    const modal = document.getElementById(pair[0]);
    modal.addEventListener('click', function (event) {
      if (event.target === modal) modal.hidden = true;
    });
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      document.getElementById('user-modal').hidden = true;
      document.getElementById('report-modal').hidden = true;
    }
  });

  loadSamples();
  showView(can('analyze') ? 'dashboard' : 'history');
});
