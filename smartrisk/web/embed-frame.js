(() => {
  const embedConfig = window.SMART_RISK_EMBED || {};
  const root = document.getElementById('widget');
  const input = document.getElementById('contract');
  const scanButton = document.getElementById('scan');
  const message = document.getElementById('message');
  const loading = document.getElementById('loading');
  const loadingTitle = document.getElementById('loading-title');
  const loadingDetail = document.getElementById('loading-detail');
  const result = document.getElementById('result');
  const verdict = document.getElementById('result-verdict');
  const network = document.getElementById('result-network');
  const score = document.getElementById('result-score');
  const address = document.getElementById('result-address');
  const primary = document.getElementById('result-primary');
  const signals = document.getElementById('result-signals');
  const meta = document.getElementById('result-meta');
  const fullReport = document.getElementById('full-report');
  const newScan = document.getElementById('new-scan');

  const params = new URLSearchParams(window.location.search);
  const theme = String(params.get('theme') || 'dark').toLowerCase();
  if (theme === 'light') document.documentElement.dataset.theme = 'light';
  if (params.get('compact') === '1') root.classList.add('compact');

  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function postHeight() {
    const height = Math.max(document.documentElement.scrollHeight, document.body.scrollHeight);
    window.parent.postMessage({ type: 'smartrisk:resize', height }, '*');
  }

  function setMessage(text = '', type = '') {
    message.textContent = text;
    message.className = `message ${type}`.trim();
  }

  function setBusy(busy) {
    scanButton.disabled = busy;
    input.disabled = busy;
    loading.hidden = !busy;
    if (busy) result.hidden = true;
  }

  function scoreClass(data) {
    const band = String(data?.risk?.band || '').toLowerCase();
    const value = Number(data?.risk?.score);
    if (band === 'critical' || value >= 80) return 'critical';
    if (band === 'high' || value >= 60) return 'high';
    if (band === 'medium' || value >= 35) return 'medium';
    if (band === 'low' || value < 35) return 'low';
    return 'unknown';
  }

  function render(data) {
    const tone = scoreClass(data);
    root.dataset.state = 'result';
    result.className = `result ${tone}`;
    verdict.textContent = String(data?.verdict?.label || 'UNVERIFIED').toUpperCase();
    network.textContent = data?.network || (data?.chain_id ? `Chain ${data.chain_id}` : 'Network unknown');
    const numericScore = Number(data?.risk?.score);
    score.textContent = Number.isFinite(numericScore) ? Math.round(numericScore) : '—';
    address.textContent = data?.address || 'Contract address unavailable';

    const title = data?.primary_detection?.title || '';
    const explanation = data?.primary_detection?.explanation || '';
    if (title && title !== 'No primary detection') {
      primary.hidden = false;
      primary.innerHTML = `<strong>${esc(title)}</strong>${explanation ? `<span>${esc(explanation)}</span>` : ''}`;
    } else {
      primary.hidden = true;
      primary.innerHTML = '';
    }

    const rows = Array.isArray(data?.signals) ? data.signals : [];
    signals.innerHTML = rows.length
      ? rows.map(item => `<div class="signal"><div><strong>${esc(item.title)}</strong><span>${esc(item.description || item.status || '')}</span></div><span class="severity ${esc(String(item.severity || 'signal').toLowerCase())}">${esc(item.severity || 'signal')}</span></div>`).join('')
      : '<div class="empty">No additional risk signals were returned.</div>';

    const confidence = data?.risk?.confidence == null ? null : Math.round(Number(data.risk.confidence) * 100);
    const coverage = data?.risk?.coverage == null ? null : Math.round(Number(data.risk.coverage) * 100);
    meta.textContent = [
      confidence == null || !Number.isFinite(confidence) ? null : `Confidence ${confidence}%`,
      coverage == null || !Number.isFinite(coverage) ? null : `Coverage ${coverage}%`,
      data?.unknowns_count ? `${data.unknowns_count} unknown item(s)` : null,
    ].filter(Boolean).join(' · ') || 'SmartRisk analysis completed.';

    fullReport.href = data?.full_report_url || '#';
    loading.hidden = true;
    result.hidden = false;
    setBusy(false);
    setMessage('');
    postHeight();
  }

  async function getJSON(url, options) {
    const response = await fetch(url, options);
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || 'Request failed.');
    return payload;
  }

  async function poll(jobId) {
    const started = Date.now();
    while (Date.now() - started < 90_000) {
      const data = await getJSON(`/v1/embed/scans/${encodeURIComponent(jobId)}`);
      if (data.status === 'complete' || data.status === 'unknown' || data.status === 'partial') {
        render(data);
        return;
      }
      if (data.status === 'failed') {
        throw new Error(data.error || 'The scan failed.');
      }
      loadingTitle.textContent = data.status === 'running' ? 'Scanning contract…' : 'Preparing scan…';
      loadingDetail.textContent = data.status === 'running' ? 'Running SmartRisk analysis.' : 'Queued for analysis.';
      postHeight();
      await new Promise(resolve => setTimeout(resolve, Math.max(700, Number(data.poll_after_ms || 1000))));
    }
    throw new Error('The scan is taking longer than expected. Please try again.');
  }

  async function scan() {
    const value = input.value.trim();
    if (!value) {
      setMessage('Enter a contract address.', 'error');
      input.focus();
      return;
    }
    setMessage('');
    root.dataset.state = 'loading';
    setBusy(true);
    loadingTitle.textContent = 'Preparing scan…';
    loadingDetail.textContent = 'SmartRisk is validating the contract and detecting the network.';
    try {
      const created = await getJSON('/v1/embed/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', ...(embedConfig.app_key ? { 'X-SmartRisk-Embed-Key': embedConfig.app_key } : {}), ...(embedConfig.token ? { 'X-SmartRisk-Embed-Token': embedConfig.token } : {}) },
        body: JSON.stringify({ address: value }),
      });
      await poll(created.job_id);
    } catch (error) {
      setBusy(false);
      root.dataset.state = 'error';
      setMessage(error instanceof Error ? error.message : 'The scan could not be completed.', 'error');
      postHeight();
    }
  }

  scanButton.addEventListener('click', scan);
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter') scan();
  });
  newScan.addEventListener('click', () => {
    result.hidden = true;
    input.disabled = false;
    scanButton.disabled = false;
    input.value = '';
    input.focus();
    root.dataset.state = 'idle';
    setMessage('');
    postHeight();
  });

  postHeight();
  input.focus();
})();
