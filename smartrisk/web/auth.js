const query = new URLSearchParams(window.location.search);
const mode = query.get('mode') || 'login';
const token = query.get('token') || '';

const title = document.getElementById('auth-title');
const copy = document.getElementById('auth-copy');
const alertBox = document.getElementById('auth-alert');
const links = document.getElementById('auth-links');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const forgotForm = document.getElementById('forgot-form');
const resendForm = document.getElementById('resend-form');
const resetForm = document.getElementById('reset-form');
const verifiedView = document.getElementById('verified-view');
const resetSuccess = document.getElementById('reset-success');
let pendingEmail = ''; 
const accountView = document.getElementById('account-view');
const accountEmail = document.getElementById('account-email');
const logoutButton = document.getElementById('logout-button');

function showAlert(message, success = false) {
  alertBox.hidden = !message;
  alertBox.textContent = message || '';
  alertBox.classList.toggle('success', success);
}

function setMode(next) {
  [loginForm, registerForm, resendForm, forgotForm, resetForm, verifiedView, resetSuccess, accountView].forEach((node) => { node.hidden = true; });
  links.hidden = true;
  showAlert('');
  if (next === 'register') {
    title.textContent = 'Create your account';
    copy.textContent = 'Create an account to manage your SmartRisk activity.';
    registerForm.hidden = false;
    links.hidden = false;
    links.innerHTML = '<a href="/auth?mode=login">Already have an account?</a><a href="/auth?mode=forgot">Forgot password?</a>';
  } else if (next === 'verify-pending') {
    title.textContent = 'Check your email';
    copy.textContent = 'We sent a verification link. Verify your address before signing in.';
    resendForm.hidden = false;
    document.getElementById('resend-email').value = pendingEmail;
    links.hidden = false;
    links.innerHTML = '<a href="/auth?mode=login">Back to login</a>';
  } else if (next === 'forgot') {
    title.textContent = 'Reset your password';
    copy.textContent = 'We will send a reset link if the account exists.';
    forgotForm.hidden = false;
    links.hidden = false;
    links.innerHTML = '<a href="/auth?mode=login">Back to login</a>';
  } else if (next === 'reset') {
    title.textContent = 'Choose a new password';
    copy.textContent = 'Set a new password for your SmartRisk account.';
    resetForm.hidden = false;
    links.hidden = false;
    links.innerHTML = '<a href="/auth?mode=login">Back to login</a>';
  } else if (next === 'verified') {
    title.textContent = 'Email verified';
    copy.textContent = '';
    verifiedView.hidden = false;
  } else if (next === 'reset-success') {
    title.textContent = 'Password updated';
    copy.textContent = '';
    resetSuccess.hidden = false;
  } else if (next === 'account') {
    title.textContent = 'Your account';
    copy.textContent = '';
    accountView.hidden = false;
    links.hidden = false;
    links.innerHTML = '<a href="/">Back to scanner</a>';
    loadAccount();
  } else {
    title.textContent = 'Welcome back';
    copy.textContent = 'Sign in to manage your SmartRisk account.';
    loginForm.hidden = false;
    links.hidden = false;
    links.innerHTML = '<a href="/auth?mode=register">Create account</a><a href="/auth?mode=forgot">Forgot password?</a>';
  }
}

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || 'Request failed.');
  return payload;
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  showAlert('');
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  try {
    const result = await post('/v1/auth/login', {email, password});
    window.location.href = result.user?.role === 'admin' ? '/admin' : '/';
  } catch (error) {
    showAlert(error.message || 'Login failed.');
  }
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  showAlert('');
  const email = document.getElementById('register-email').value.trim();
  const password = document.getElementById('register-password').value;
  const confirm = document.getElementById('register-confirm').value;
  if (password !== confirm) { showAlert('Passwords do not match.'); return; }
  try {
    await post('/v1/auth/register', {email, password});
    pendingEmail = email;
    registerForm.reset();
    setMode('verify-pending');
    showAlert('Verification email sent. Check your inbox.', true);
  } catch (error) {
    showAlert(error.message || 'Could not create account.');
  }
});

resendForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  showAlert('');
  const email = document.getElementById('resend-email').value.trim();
  try {
    await post('/v1/auth/resend-verification', {email});
    showAlert('If the account is eligible, a new verification email has been sent.', true);
  } catch (error) {
    showAlert(error.message || 'Could not resend the verification email.');
  }
});

forgotForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  showAlert('');
  const email = document.getElementById('forgot-email').value.trim();
  try {
    await post('/v1/auth/forgot-password', {email});
    showAlert('If an account exists for that email, a reset link has been sent.', true);
  } catch (error) {
    showAlert(error.message || 'Could not process the request.');
  }
});

resetForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  showAlert('');
  const password = document.getElementById('reset-password').value;
  const confirm = document.getElementById('reset-confirm').value;
  if (password !== confirm) { showAlert('Passwords do not match.'); return; }
  try {
    await post('/v1/auth/reset-password', {token, password});
    setMode('reset-success');
  } catch (error) {
    showAlert(error.message || 'Could not reset password.');
  }
});

setMode(mode);


async function loadAccount() {
  try {
    const response = await fetch('/v1/auth/me', {cache: 'no-store'});
    const payload = await response.json();
    if (!payload.authenticated) {
      window.location.href = '/auth?mode=login';
      return;
    }
    if (payload.user?.role === 'admin') {
      window.location.href = '/admin';
      return;
    }
    accountEmail.textContent = payload.user.email + (payload.user.email_verified ? ' · Verified' : '');
  } catch (_) {
    window.location.href = '/auth?mode=login';
  }
}

logoutButton.addEventListener('click', async () => {
  try { await fetch('/v1/auth/logout', {method: 'POST'}); } finally { window.location.href = '/'; }
});
