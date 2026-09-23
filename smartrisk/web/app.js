const form = document.getElementById('scan-form');
const tokenInput = document.getElementById('token');
const scanButton = document.getElementById('scan-button');
const formMessage = document.getElementById('form-message');
const scanStatus = document.getElementById('scan-status');
const statusText = document.getElementById('status-text');

function isAddress(value) {
  return /^0x[a-fA-F0-9]{40}$/.test(value.trim());
}

function setError(message) {
  formMessage.textContent = message || '';
}

function setLoading(loading) {
  scanButton.disabled = loading;
  scanButton.classList.toggle('loading', loading);
}

async function submitScan(tokenAddress) {
  const response = await fetch('/v1/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token_address: tokenAddress })
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || 'Scan could not be started.');
  return payload;
}

async function poll(jobId) {
  const startedAt = Date.now();
  while (true) {
    if (Date.now() - startedAt > 180000) {
      throw new Error('The scan is still running. Please keep this page open and refresh later.');
    }
    const response = await fetch(`/v1/scans/${encodeURIComponent(jobId)}`);
    if (!response.ok) throw new Error('Scan status could not be loaded.');
    const payload = await response.json();
    if (payload.status === 'complete' || payload.status === 'partial' || payload.status === 'unknown' || payload.status === 'failed') {
      return payload;
    }
    const stage = String(payload.progress_stage || 'analysis').replaceAll('_', ' ');
    const pct = Number.isFinite(Number(payload.progress_percent)) ? ` ${Math.max(0, Math.min(100, Number(payload.progress_percent)))}%` : '';
    statusText.textContent = `Analyzing ${stage}…${pct}`;
    await new Promise((resolve) => setTimeout(resolve, Math.max(500, Number(payload.poll_after_ms || 1000))));
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  setError('');
  scanStatus.hidden = true;

  const tokenAddress = tokenInput.value.trim();
  if (!isAddress(tokenAddress)) {
    setError('Enter a valid EVM contract address.');
    tokenInput.focus();
    return;
  }

  setLoading(true);
  scanStatus.hidden = false;
  statusText.textContent = 'Detecting network…';

  try {
    const job = await submitScan(tokenAddress);
    statusText.textContent = 'Scan queued…';
    const finalJob = await poll(job.job_id);
    if (finalJob.status === 'failed') {
      throw new Error(finalJob.error || 'The scan failed.');
    }
    window.location.href = `/scan/${encodeURIComponent(job.job_id)}`;
  } catch (error) {
    setError(error instanceof Error ? error.message : 'Scan could not be completed.');
    scanStatus.hidden = true;
  } finally {
    setLoading(false);
  }
});



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
  } catch (_) { /* account UI is non-blocking */ }
}
loadAccountControl();
