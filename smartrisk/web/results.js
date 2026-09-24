const pathParts = window.location.pathname.split('/').filter(Boolean);
const jobId = decodeURIComponent(pathParts[0] === 'scan' ? pathParts.slice(1).join('/') : '');

const els = {
  gauge: document.getElementById('gauge'),
  riskScore: document.getElementById('risk-score'),
  riskCaption: document.getElementById('risk-caption'),
  networkName: document.getElementById('network-name'),
  contractAddress: document.getElementById('contract-address'),
  riskTitle: document.getElementById('risk-title'),
  riskExplanation: document.getElementById('risk-explanation'),
  topBadges: document.getElementById('top-badges'),
  sourceStrip: document.getElementById('source-strip'),
  reportMeta: document.getElementById('report-meta'),
  copyAddress: document.getElementById('copy-address'),
  honeypotCard: document.getElementById('honeypot-card'),
  honeypotStatus: document.getElementById('honeypot-status'),
  honeypotDetail: document.getElementById('honeypot-detail'),
  liquidityCard: document.getElementById('liquidity-card'),
  liquidityStatus: document.getElementById('liquidity-status'),
  liquidityDetail: document.getElementById('liquidity-detail'),
  holdersCard: document.getElementById('holders-card'),
  holdersStatus: document.getElementById('holders-status'),
  holdersDetail: document.getElementById('holders-detail'),
  ownershipCard: document.getElementById('ownership-card'),
  ownershipStatus: document.getElementById('ownership-status'),
  ownershipDetail: document.getElementById('ownership-detail'),
  permissionsContent: document.getElementById('permissions-content'),
  vulnerabilitiesContent: document.getElementById('vulnerabilities-content'),
  technicalContent: document.getElementById('technical-content'),
};

const networkNames = new Map();

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function first(list, predicate) {
  return Array.isArray(list) ? list.find(predicate) : undefined;
}

function featuresOf(heuristics) {
  return heuristics?.report?.risk?.features || [];
}

function feature(features, id) {
  return first(features, item => item?.feature_id === id)?.value;
}

function heuristicSummary(report) {
  return first(report?.engines, item => item?.name === 'heuristics');
}

function stateForkSummary(report) {
  return first(report?.engines, item => item?.name === 'state_fork');
}

function publicSignals(report) {
  if (Array.isArray(report?.signals)) return report.signals;
  if (Array.isArray(report?.findings)) return report.findings;
  return [];
}

function featureText(value, unit) {
  if (value === undefined || value === null || value === '') return 'Not verified';
  if (unit === 'ratio') return `${(Number(value) * 100).toFixed(1)}%`;
  if (unit === 'usd') return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(Number(value));
  if (unit === 'count') return Number(value).toLocaleString('en-US');
  return String(value);
}

function scoreClass(score, band) {
  const lower = String(band || '').toLowerCase();
  if (lower === 'critical' || Number(score) >= 80) return 'critical';
  if (lower === 'high' || Number(score) >= 60) return 'bad';
  if (lower === 'medium' || Number(score) >= 35) return 'warn';
  return 'good';
}

function setCard(card, valueEl, detailEl, tone, value, detail) {
  card.classList.remove('good', 'warn', 'bad', 'neutral');
  card.classList.add(tone);
  valueEl.textContent = value;
  detailEl.textContent = detail;
}

function renderGauge(report) {
  const score = report?.risk?.score;
  const band = report?.risk?.band || 'unknown';
  const n = Number.isFinite(Number(score)) ? Math.max(0, Math.min(100, Number(score))) : null;
  const tone = scoreClass(n ?? 0, band);
  const angle = n === null ? 0 : n * 3.6;
  const color = tone === 'critical' ? '#ff4f3b' : tone === 'bad' ? '#ff6956' : tone === 'warn' ? '#ffb23e' : '#6de0a7';
  els.gauge.style.background = n === null
    ? 'conic-gradient(#70869b 0deg, #70869b 26deg, rgba(255,255,255,0.08) 26deg, rgba(255,255,255,0.08) 360deg)'
    : `conic-gradient(${color} 0deg, ${color} ${angle}deg, rgba(255,255,255,0.08) ${angle}deg, rgba(255,255,255,0.08) 360deg)`;
  els.riskScore.textContent = n === null ? '—' : Math.round(n);
  els.riskCaption.textContent = String(report?.verdict?.label || `${String(band).toUpperCase()} RISK`).toUpperCase();
}

function renderBadges(report) {
  const rawDimensions = report?.risk_dimensions || {};
  const dimensions = Array.isArray(rawDimensions) ? Object.fromEntries(rawDimensions.map(item => [item.id, item])) : rawDimensions;
  const badgeData = [
    ['Source', dimensions.contract_security, 'contract_security'],
    ['Controls', dimensions.ownership_security, 'ownership_security'],
    ['Trading', dimensions.trading_security, 'trading_security'],
    ['Liquidity', dimensions.liquidity_market, 'liquidity_market'],
    ['Holders', dimensions.holder_distribution, 'holder_distribution'],
    ['History', dimensions.historical_behavior, 'historical_behavior'],
  ];
  els.topBadges.innerHTML = badgeData.map(([label, dim]) => {
    const signals = Number(dim?.signals || 0);
    const tone = signals > 0 ? 'warn' : 'neutral';
    return `<span class="top-badge ${tone}"><i></i>${esc(label)}</span>`;
  }).join('');

  const engines = Array.isArray(report?.engines) ? report.engines : [];
  const isPublic = !Array.isArray(report?.engines);
  const pills = [
    ['Source', engines.some(e => e.name === 'static_ast' && e.status === 'complete')],
    ['Controls', engines.some(e => e.name === 'static_ast' && e.status === 'complete') || engines.some(e => e.name === 'heuristics' && e.status === 'complete')],
    ['Trading', engines.some(e => e.name === 'state_fork' && e.status === 'complete')],
    ['Liquidity', feature(featuresOf(heuristicSummary(report)), 'liquidity.pair_count_analyzed') !== undefined || feature(featuresOf(heuristicSummary(report)), 'market.best_liquidity_usd') !== undefined],
    ['Holders', feature(featuresOf(heuristicSummary(report)), 'holders.holder_count') !== undefined],
    ['History', feature(featuresOf(heuristicSummary(report)), 'history.transfer_count') !== undefined],
  ];
  els.sourceStrip.innerHTML = pills.map(([label, ready]) => `<span class="coverage-pill ${ready ? '' : 'neutral'}"><i></i>${esc(label)}</span>`).join('');
}

function renderOverview(report) {
  const isPublic = !Array.isArray(report?.engines);
  const heuristic = heuristicSummary(report);
  const features = featuresOf(heuristic);
  const fork = stateForkSummary(report);
  const verdict = report?.verdict || {};
  const risk = report?.risk || {};
  const primary = verdict?.primary_detection || {};

  renderGauge(risk);

  const request = window.__scanRequest || {};
  const chainId = request.chain_id || report?.chain_id;
  els.networkName.textContent = networkNames.get(String(chainId)) || report?.network || (chainId ? `Chain ${chainId}` : 'Network unknown');
  els.contractAddress.textContent = request.token_address || report?.address || 'Contract address unavailable';

  els.riskTitle.textContent = verdict.label || 'UNVERIFIED';
  els.riskExplanation.textContent = primary.explanation || primary.title || 'SmartRisk did not produce a stronger primary detection from the available evidence.';

  const forkComplete = fork?.status === 'complete';
  const honeypotDetected = verdict.code === 'HONEYPOT_DETECTED';
  if (honeypotDetected) {
    setCard(els.honeypotCard, els.honeypotStatus, els.honeypotDetail, 'bad', 'Sell blocked', 'A sell restriction was reproduced after a successful buy in the anchored fork.');
  } else if (forkComplete) {
    setCard(els.honeypotCard, els.honeypotStatus, els.honeypotDetail, 'good', 'No sell block detected', 'State-Fork trading checks completed for the selected scenarios.');
  } else {
    setCard(els.honeypotCard, els.honeypotStatus, els.honeypotDetail, 'neutral', 'Not verified', 'State-Fork evidence is incomplete or unavailable.');
  }

  const bestLiquidity = feature(features, 'market.best_liquidity_usd');
  const lpShare = feature(features, 'liquidity.max_lp_top1_share');
  const pairCount = feature(features, 'liquidity.pair_count_analyzed') ?? feature(features, 'market.pair_count');
  setCard(
    els.liquidityCard,
    els.liquidityStatus,
    els.liquidityDetail,
    bestLiquidity === undefined ? 'neutral' : Number(bestLiquidity) < 50000 ? 'warn' : 'good',
    bestLiquidity === undefined ? 'Not verified' : featureText(bestLiquidity, 'usd'),
    [
      pairCount === undefined ? null : `${featureText(pairCount, 'count')} pair(s) analyzed`,
      lpShare === undefined ? null : `Top LP share: ${featureText(lpShare, 'ratio')}`,
    ].filter(Boolean).join(' · ') || 'Liquidity evidence unavailable.',
  );

  const holderCount = feature(features, 'holders.holder_count');
  const top10 = feature(features, 'holders.top10_concentration');
  const holderTone = top10 === undefined ? 'neutral' : Number(top10) >= 0.5 ? 'warn' : 'good';
  setCard(
    els.holdersCard,
    els.holdersStatus,
    els.holdersDetail,
    holderTone,
    holderCount === undefined ? 'Not verified' : `${featureText(holderCount, 'count')} holders`,
    top10 === undefined ? 'Holder concentration unavailable.' : `Top 10 concentration: ${featureText(top10, 'ratio')}`,
  );

  const ownerObserved = feature(features, 'contract.owner_observed');
  const adminObserved = feature(features, 'contract.admin_observed');
  const proxyDetected = feature(features, 'contract.proxy_detected');
  const ownershipTone = ownerObserved === undefined && adminObserved === undefined ? 'neutral' : (ownerObserved || adminObserved || proxyDetected) ? 'warn' : 'good';
  setCard(
    els.ownershipCard,
    els.ownershipStatus,
    els.ownershipDetail,
    ownershipTone,
    ownerObserved === undefined ? 'Not verified' : ownerObserved ? 'Owner observed' : 'Owner not observed',
    `Admin: ${adminObserved === undefined ? 'unknown' : adminObserved ? 'observed' : 'not observed'} · Upgradeable: ${proxyDetected === undefined ? 'unknown' : proxyDetected ? 'yes' : 'no'}`,
  );

  renderBadges(report);
  if (isPublic) {
    renderPublicSummary(report);
  } else {
    renderPermissions(report, features);
    renderVulnerabilities(report);
    renderTechnical(report);
  }

  const version = report?.versions?.release || '0.9.0';
  const coverage = risk?.coverage == null ? null : `${Math.round(Number(risk.coverage) * 100)}% coverage`;
  els.reportMeta.textContent = `SmartRisk ${version}${coverage ? ` · ${coverage}` : ''} · Run ${report?.run_id || '—'}`;
}

function renderPermissions(report, features) {
  const rows = [
    ['Owner', feature(features, 'contract.owner_observed') === undefined ? 'Unknown' : feature(features, 'contract.owner_observed') ? 'Observed' : 'Not observed', 'Control signal from contract intelligence.'],
    ['Admin', feature(features, 'contract.admin_observed') === undefined ? 'Unknown' : feature(features, 'contract.admin_observed') ? 'Observed' : 'Not observed', 'Administrative role visibility.'],
    ['Upgradeable', feature(features, 'contract.proxy_detected') === undefined ? 'Unknown' : feature(features, 'contract.proxy_detected') ? 'Detected' : 'Not detected', 'Proxy / implementation signal.'],
  ];
  const ownershipFindings = (report?.findings || []).filter(item => /owner|admin|upgrade|privilege|role/i.test(`${item.rule_id} ${item.title} ${item.description}`)).slice(0, 6);
  els.permissionsContent.innerHTML = `
    <div class="rows">
      ${rows.map(([title, value, detail]) => `<div class="data-row"><div class="data-main"><div class="data-title">${esc(title)}</div><div class="data-sub">${esc(detail)}</div></div><div class="data-value">${esc(value)}</div></div>`).join('')}
      ${ownershipFindings.map(item => `<div class="data-row"><div class="data-main"><div class="data-title">${esc(item.title || item.rule_id || 'Permission finding')}<span class="severity ${esc(String(item.severity || '').toLowerCase())}">${esc(item.severity || 'signal')}</span></div><div class="data-sub">${esc(item.description || '')}</div></div><div class="data-value">${esc(item.status || 'likely')}</div></div>`).join('')}
    </div>`;
}

function renderVulnerabilities(report) {
  const findings = [...publicSignals(report)];
  findings.sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    return (rank[String(a.severity || '').toLowerCase()] ?? 9) - (rank[String(b.severity || '').toLowerCase()] ?? 9);
  });
  const visible = findings.slice(0, 18);
  if (!visible.length) {
    els.vulnerabilitiesContent.innerHTML = '<div class="empty-state">No findings were returned in the current evidence set.</div>';
    return;
  }
  els.vulnerabilitiesContent.innerHTML = `<div class="rows">${visible.map(item => `
    <div class="data-row">
      <div class="data-main">
        <div class="data-title">${esc(item.title || item.rule_id || 'Finding')}<span class="severity ${esc(String(item.severity || '').toLowerCase())}">${esc(item.severity || 'signal')}</span></div>
        <div class="data-sub">${esc(item.description || '')}</div>
      </div>
      <div class="data-value">${esc(item.status || 'observed')}</div>
    </div>`).join('')}</div>`;
}


function renderPublicSummary(report) {
  const signals = publicSignals(report).slice(0, 5);
  const dimensions = Array.isArray(report?.risk_dimensions) ? report.risk_dimensions : [];
  const engines = Array.isArray(report?.engine_statuses) ? report.engine_statuses : [];
  const unknowns = Array.isArray(report?.unknowns) ? report.unknowns : [];
  els.permissionsContent.innerHTML = `<div class="rows"><div class="data-row"><div class="data-main"><div class="data-title">Verification</div><div class="data-sub">Coverage and confidence reflect the available public scan evidence.</div></div><div class="data-value">${esc(report?.risk?.coverage == null ? 'Unknown' : `${Math.round(Number(report.risk.coverage) * 100)}%`)}</div></div></div>`;
  els.vulnerabilitiesContent.innerHTML = signals.length ? `<div class="rows">${signals.map(item => `<div class="data-row"><div class="data-main"><div class="data-title">${esc(item.title || 'Risk signal')}<span class="severity ${esc(String(item.severity || '').toLowerCase())}">${esc(item.severity || 'signal')}</span></div><div class="data-sub">${esc(item.description || '')}</div></div><div class="data-value">${esc(item.status || 'observed')}</div></div>`).join('')}</div>` : '<div class="empty-state">No major signals were returned in the current scan.</div>';
  const engineRows = engines.map(item => `<div class="data-row"><div class="data-main"><div class="data-title">${esc(item.name || 'Engine')}</div><div class="data-sub">${esc(item.unknowns_count ? `${item.unknowns_count} evidence gap(s)` : 'Evidence returned')}</div></div><div class="data-value">${esc(item.status || 'unknown')}</div></div>`).join('');
  const unknownRows = unknowns.slice(0, 6).map(item => `<div class="data-row"><div class="data-main"><div class="data-title">Evidence gap</div><div class="data-sub">${esc(item)}</div></div><div class="data-value">Review</div></div>`).join('');
  els.technicalContent.innerHTML = `<div class="rows">${engineRows}${dimensions.map(item => `<div class="data-row"><div class="data-main"><div class="data-title">${esc(item.label || item.id || 'Risk dimension')}</div><div class="data-sub">${esc(item.severity || 'unknown')} · ${esc(item.signals == null ? 'No signal count' : `${item.signals} signal(s)`)}</div></div><div class="data-value">Public</div></div>`).join('')}${unknownRows}<div class="data-row"><div class="data-main"><div class="data-title">Full report</div><div class="data-sub">Available through an eligible paid API key.</div></div><div class="data-value">Locked</div></div></div>`;
}

function renderTechnical(report) {
  const engines = Array.isArray(report?.engines) ? report.engines : [];
  const anchor = report?.job?.anchor;
  const consistency = report?.job?.anchor_consistency;
  const rows = engines.map(item => [
    item.name,
    `${item.status} · ${Math.round(Number(item.coverage || 0) * 100)}% coverage`,
    `${Math.round(Number(item.confidence || 0) * 100)}% confidence`,
  ]);
  if (anchor) rows.push(['Canonical anchor', `${anchor.chain_id || '—'} · block ${anchor.block_number ?? '—'}`, consistency?.status || 'unknown']);
  if (report?.unknowns?.length) rows.push(['Unknowns', `${report.unknowns.length} unresolved item(s)`, 'review']);

  els.technicalContent.innerHTML = `<div class="rows">${rows.map(([title, value, right]) => `
    <div class="data-row"><div class="data-main"><div class="data-title">${esc(title)}</div><div class="data-sub">${esc(value)}</div></div><div class="data-value">${esc(right)}</div></div>`).join('')}</div>`;
}

function showError(message) {
  document.querySelector('.report').innerHTML = `
    <div class="error-screen">
      <h1>Scan result unavailable</h1>
      <p>${esc(message)}</p>
      <a href="/">Return to scanner</a>
    </div>`;
}

async function loadNetworks() {
  try {
    const response = await fetch('/v1/networks');
    if (!response.ok) return;
    const payload = await response.json();
    for (const network of payload.networks || []) networkNames.set(String(network.chain_id), network.name);
  } catch {
    // The result remains usable without friendly network labels.
  }
}

async function loadResult() {
  if (!jobId) {
    showError('No scan ID was provided.');
    return;
  }
  await loadNetworks();
  const response = await fetch(`/v1/scans/${encodeURIComponent(jobId)}`);
  const job = await response.json().catch(() => ({}));
  if (!response.ok) {
    showError(job.error || 'The scan could not be loaded.');
    return;
  }
  if (job.status === 'pending' || job.status === 'running') {
    window.location.href = `/?job=${encodeURIComponent(jobId)}`;
    return;
  }
  if (job.status === 'failed') {
    showError(job.error || 'The scan failed.');
    return;
  }
  // /v1/scans/:id intentionally returns the public report envelope directly
  // (risk, verdict, signals, dimensions). It does not expose the internal
  // persisted `result` object. Keep the page contract aligned with that API.
  const report = job.result || job;
  if (!report.risk || !report.verdict) {
    showError('This scan does not contain a completed report yet.');
    return;
  }
  window.__scanRequest = {
    ...(job.request || {}),
    token_address: job.request?.token_address || job.address,
    chain_id: job.request?.chain_id || job.chain_id,
  };
  renderOverview(report);
}

document.querySelectorAll('.module-card').forEach(button => {
  button.addEventListener('click', () => {
    const target = document.getElementById(button.dataset.panel);
    if (!target) return;
    target.hidden = !target.hidden;
    if (!target.hidden) target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
});

document.querySelectorAll('.panel-close').forEach(button => {
  button.addEventListener('click', () => {
    const panel = button.closest('.detail-panel');
    if (panel) panel.hidden = true;
  });
});

els.copyAddress.addEventListener('click', async () => {
  const address = els.contractAddress.textContent.trim();
  if (!address || address === '—' || !navigator.clipboard) return;
  try {
    await navigator.clipboard.writeText(address);
    els.copyAddress.textContent = 'Copied';
    setTimeout(() => { els.copyAddress.textContent = 'Copy'; }, 1300);
  } catch {
    // Clipboard may be disabled by the browser context.
  }
});

loadResult().catch((error) => showError(error instanceof Error ? error.message : 'The scan result could not be loaded.'));


async function loadAccountControl() {
  const control = document.getElementById('account-link');
  if (!control) return;
  try {
    const response = await fetch('/v1/auth/me', {cache: 'no-store'});
    const payload = await response.json();
    if (payload.authenticated && payload.user) {
      control.textContent = 'Account';
      control.href = '/auth?mode=account';
      control.title = payload.user.email;
    }
  } catch (_) {}
}
loadAccountControl();
