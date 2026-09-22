const alertBox = document.getElementById('dev-alert');
const planBadge = document.getElementById('plan-badge');
const usageEl = document.getElementById('usage');
const plansEl = document.getElementById('plans');
const keyList = document.getElementById('key-list');
const createKeyButton = document.getElementById('create-key');
const keyName = document.getElementById('key-name');
const newKey = document.getElementById('new-key');
const newKeyValue = document.getElementById('new-key-value');
const copyKey = document.getElementById('copy-key');
const billingEl = document.getElementById('billing');
let currentInvoice = null;
function showAlert(message, success = false) { alertBox.hidden = !message; alertBox.textContent = message || ''; alertBox.classList.toggle('success', success); }
async function request(path, options = {}) {
  const response = await fetch(path, {cache: 'no-store', ...options});
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) { window.location.href = '/auth?mode=login'; throw new Error('Authentication required.'); }
  if (!response.ok) throw new Error(payload.error || 'Request failed.');
  return payload;
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function renderKeys(keys) {
  keyList.innerHTML = keys.length ? keys.map((key) => `<div class="key-row"><div><strong>${escapeHtml(key.name)}</strong><div class="status">${escapeHtml(key.prefix)}••••${escapeHtml(key.last4)} · ${escapeHtml(key.status)}</div></div>${key.status === 'active' ? `<button class="secondary revoke" data-id="${escapeHtml(key.id)}">Revoke</button>` : ''}</div>`).join('') : '<p class="muted">No API keys yet.</p>';
  keyList.querySelectorAll('.revoke').forEach((button) => button.addEventListener('click', () => revokeKey(button.dataset.id)));
}
function renderPlans(plans) {
  plansEl.innerHTML = plans.map((plan) => `<div class="plan ${currentInvoice?.plan_id === plan.id ? 'selected' : ''}"><div class="plan-title-row"><strong>${escapeHtml(plan.name)}</strong><span class="price">${Number(plan.price_usdt).toFixed(2)} USDT / 30 days</span></div><div class="plan-grid"><span>${plan.monthly_scan_limit.toLocaleString()} scans/month</span><span>${plan.batch_limit.toLocaleString()} / batch</span><span>${plan.requests_per_second} RPS</span><span>${plan.concurrency} concurrency</span></div>${plan.active && Number(plan.price_usdt) > 0 ? `<button class="subscribe" data-plan="${escapeHtml(plan.id)}">${currentInvoice?.plan_id === plan.id ? 'View payment' : 'Subscribe'}</button>` : ''}</div>`).join('');
  plansEl.querySelectorAll('.subscribe').forEach((button) => button.addEventListener('click', () => subscribe(button.dataset.plan)));
}
function renderBilling(config) {
  billingEl.hidden = false;
  if (!config.billing_enabled) { billingEl.innerHTML = '<div class="billing-disabled"><strong>Crypto billing is not enabled.</strong><p class="muted">Enable billing and configure the Ethereum receiving address on the server to accept payments.</p></div>'; return; }
  billingEl.innerHTML = `<div class="card-head"><div><h2>USDT payment</h2><p class="muted">Ethereum Mainnet · exact amount required.</p></div><span class="badge">USDT / Ethereum</span></div><div id="invoice-panel" class="invoice-panel"></div>`;
  updateInvoicePanel();
}
function updateInvoicePanel() {
  const panel = document.getElementById('invoice-panel'); if (!panel) return;
  if (!currentInvoice) { panel.innerHTML = '<p class="muted">Choose a plan above to create a payment invoice.</p>'; return; }
  const ready = ['awaiting_payment','payment_detected','confirming'].includes(currentInvoice.status);
  panel.innerHTML = `<div class="invoice-grid"><div><span>Plan</span><strong>${escapeHtml(currentInvoice.plan_id)}</strong></div><div><span>Exact amount</span><strong>${escapeHtml(currentInvoice.payment_amount_usdt)} USDT</strong></div><div><span>Network</span><strong>Ethereum Mainnet</strong></div><div><span>Status</span><strong>${escapeHtml(currentInvoice.status)}</strong></div></div><div class="address-box"><small>Send USDT to this address</small><code>${escapeHtml(currentInvoice.receiver_address)}</code></div><div class="invoice-actions">${ready ? '<button id="wallet-pay" class="subscribe">Pay with wallet</button>' : ''}<button id="copy-payment" class="secondary">Copy address</button></div><p class="muted invoice-note">Expires: ${escapeHtml(new Date(currentInvoice.expires_at).toLocaleString())}. The subscription activates only after the blockchain payment is verified and finalized.</p><div class="tx-verify"><input id="tx-hash" placeholder="Paste transaction hash for manual verification" inputmode="text"><button id="verify-tx" class="secondary">Verify payment</button></div>`;
  document.getElementById('copy-payment')?.addEventListener('click', async () => { await navigator.clipboard.writeText(currentInvoice.receiver_address); showAlert('Payment address copied.', true); });
  document.getElementById('wallet-pay')?.addEventListener('click', payWithWallet);
  document.getElementById('verify-tx')?.addEventListener('click', verifyTransaction);
}
async function subscribe(planId) {
  showAlert('');
  try {
    const payer = window.ethereum ? await getWalletAddress(false) : null;
    const data = await request('/v1/billing/invoices', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({plan_id:planId, payer_address:payer})});
    currentInvoice = data.invoice; renderPlans((await request('/v1/developer/plans')).plans); updateInvoicePanel(); showAlert('Invoice created. Pay the exact USDT amount shown below.', true); document.getElementById('billing')?.scrollIntoView({behavior:'smooth'});
  } catch (error) { showAlert(error.message || 'Could not create payment invoice.'); }
}
async function getWalletAddress(connect = true) {
  if (!window.ethereum) return null;
  const accounts = await window.ethereum.request({method: connect ? 'eth_requestAccounts' : 'eth_accounts'});
  return accounts?.[0]?.toLowerCase() || null;
}
async function ensureEthereumMainnet() {
  if (await window.ethereum.request({method:'eth_chainId'}) === '0x1') return;
  await window.ethereum.request({method:'wallet_switchEthereumChain', params:[{chainId:'0x1'}]});
}
function encodeTransfer(to, amountUnits) { return `0xa9059cbb${to.toLowerCase().replace(/^0x/,'').padStart(64,'0')}${BigInt(amountUnits).toString(16).padStart(64,'0')}`; }
async function payWithWallet() {
  if (!window.ethereum) return showAlert('No Ethereum wallet was detected. Send the exact amount manually and paste the transaction hash.');
  try {
    const payer = await getWalletAddress(true); await ensureEthereumMainnet();
    const currentPayer = currentInvoice.expected_payer_address?.toLowerCase();
    if (currentPayer && currentPayer !== payer) throw new Error('The connected wallet does not match this invoice.');
    const txHash = await window.ethereum.request({method:'eth_sendTransaction', params:[{from:payer, to:currentInvoice.token_contract, value:'0x0', data:encodeTransfer(currentInvoice.receiver_address,currentInvoice.payment_amount_units)}]});
    showAlert('Transaction submitted. Verifying it on Ethereum…', true);
    await applyVerification(txHash);
  } catch (error) { showAlert(error.message || 'Wallet payment failed.'); }
}
async function verifyTransaction() { const value = document.getElementById('tx-hash')?.value.trim(); if (!value) return showAlert('Enter the transaction hash.'); try { await applyVerification(value); } catch (error) { showAlert(error.message || 'Could not verify payment.'); } }
async function applyVerification(txHash) {
  const result = await request(`/v1/billing/invoices/${encodeURIComponent(currentInvoice.id)}/verify`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx_hash:txHash})});
  currentInvoice = result.invoice; updateInvoicePanel();
  if (currentInvoice.status === 'paid') { showAlert('Payment confirmed and your subscription is active.', true); await load(); }
  else showAlert('Payment detected. It will activate automatically after Ethereum finality.', true);
}
async function load() {
  try {
    const data = await request('/v1/developer');
    planBadge.textContent = data.plan?.name || 'No subscription';
    usageEl.innerHTML = data.plan ? `${data.usage.scans_reserved.toLocaleString()} / ${data.plan.monthly_scan_limit.toLocaleString()}<small>${data.usage.scans_remaining.toLocaleString()} scans remaining · ${data.billing_status === 'active' ? 'Subscription active' : 'Subscription required'}</small>` : '0 / 0<small>No active subscription · choose a plan below</small>';
    renderKeys(data.api_keys || []);
    const plans = await request('/v1/developer/plans'); const billing = await request('/v1/billing/plans');
    renderPlans(plans.plans); renderBilling(billing);
    const latest = await request('/v1/billing/invoices/latest'); if (latest.invoice) { currentInvoice = latest.invoice; renderPlans(plans.plans); updateInvoicePanel(); }
  } catch (error) { showAlert(error.message || 'Could not load developer access.'); }
}
createKeyButton.addEventListener('click', async () => { showAlert(''); try { const data = await request('/v1/developer/api-keys', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:keyName.value.trim() || 'Default key'})}); newKey.hidden=false; newKeyValue.textContent=data.key; keyName.value=''; renderKeys((await request('/v1/developer/api-keys')).api_keys); } catch (error) { showAlert(error.message || 'Could not create the key.'); } });
copyKey.addEventListener('click', async () => { await navigator.clipboard.writeText(newKeyValue.textContent); showAlert('API key copied to clipboard.', true); });
async function revokeKey(id) { if (!confirm('Revoke this API key?')) return; try { await request(`/v1/developer/api-keys/${encodeURIComponent(id)}`,{method:'POST'}); renderKeys((await request('/v1/developer/api-keys')).api_keys); showAlert('API key revoked.', true); } catch (error) { showAlert(error.message || 'Could not revoke the key.'); } }
load();
