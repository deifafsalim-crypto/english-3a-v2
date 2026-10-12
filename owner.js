/* Signing authority lives only in the unlocked in-memory CryptoKey. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const login = byId('ownerLogin');
  const workspace = byId('ownerWorkspace');
  const password = byId('ownerPassword');
  const request = byId('requestInput');
  const output = byId('codeOutput');
  const result = byId('result');
  const status = byId('status');
  const unlockButton = byId('unlockButton');
  const issueButton = byId('issueButton');
  const IDLE_MS = 10 * 60 * 1000;
  let signingKey = null;
  let epoch = 0;
  let lastActivity = 0;
  let signing = false;
  let unlocking = false;
  let timeout;

  function message(text, error = false) {
    status.textContent = text;
    status.dataset.error = String(error);
  }

  function lock(text = 'الأداة مقفلة. أدخلي كلمة المرور للمتابعة.', focus = true) {
    epoch++;
    signingKey = null;
    signing = false;
    unlocking = false;
    clearTimeout(timeout);
    password.value = '';
    password.type = 'password';
    password.readOnly = false;
    byId('togglePassword').textContent = 'إظهار';
    byId('togglePassword').setAttribute('aria-label', 'إظهار كلمة المرور');
    byId('togglePassword').setAttribute('aria-pressed', 'false');
    request.value = '';
    request.readOnly = false;
    output.value = '';
    result.hidden = true;
    workspace.hidden = true;
    login.hidden = false;
    issueButton.disabled = false;
    unlockButton.disabled = false;
    message(text);
    if (focus) password.focus();
  }

  function expired() {
    if (signingKey && Date.now() - lastActivity >= IDLE_MS) {
      lock('انتهت جلسة الإصدار بعد فترة بدون استخدام. أدخلي كلمة المرور مجددًا.');
      return true;
    }
    return false;
  }

  function activity() {
    if (!signingKey || expired()) return;
    lastActivity = Date.now();
    clearTimeout(timeout);
    timeout = setTimeout(expired, IDLE_MS + 10);
  }

  document.addEventListener('pointerdown', activity, { passive: true });
  document.addEventListener('keydown', activity);
  document.addEventListener('input', activity);
  document.addEventListener('visibilitychange', expired);
  window.addEventListener('pagehide', () => lock('الأداة مقفلة. أدخلي كلمة المرور للمتابعة.', false));
  byId('lockOwner').addEventListener('click', () => lock());

  byId('togglePassword').addEventListener('click', () => {
    const show = password.type === 'password';
    password.type = show ? 'text' : 'password';
    byId('togglePassword').textContent = show ? 'إخفاء' : 'إظهار';
    byId('togglePassword').setAttribute('aria-label', show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور');
    byId('togglePassword').setAttribute('aria-pressed', String(show));
  });

  byId('unlockForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (unlocking || signingKey) return;
    const operation = ++epoch;
    unlocking = true;
    unlockButton.disabled = true;
    password.readOnly = true;
    message('جارٍ فتح أداة الإصدار…');
    try {
      const key = await AtomicIssuerCrypto.unlock(window.ATOMIC_ISSUER_VAULT, password.value);
      const probe = '0'.repeat(32);
      const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, AtomicActivation.payload(probe));
      const valid = await AtomicActivation.verify(AtomicActivation.token(probe, signature), probe, window.ATOMIC_ACTIVATION_PUBLIC_KEY);
      if (!valid) throw new Error('Issuer mismatch');
      if (operation !== epoch) return;
      signingKey = key;
      password.value = '';
      login.hidden = true;
      workspace.hidden = false;
      lastActivity = Date.now();
      activity();
      message('الأداة جاهزة. الصقي رقم طلب المشترك.');
      request.focus();
    } catch (_) {
      if (operation !== epoch) return;
      password.value = '';
      message('كلمة المرور غير صحيحة أو تعذر فتح الأداة. انسخي كلمة المرور من ملف بيانات الدخول وحاولي مجددًا.', true);
      password.focus();
    } finally {
      if (operation === epoch) {
        unlocking = false;
        unlockButton.disabled = false;
        password.readOnly = false;
      }
    }
  });

  request.addEventListener('input', () => { result.hidden = true; output.value = ''; message(''); });
  byId('issueForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (expired() || !signingKey || signing) return;
    result.hidden = true;
    output.value = '';
    const id = AtomicActivation.normalizeRequest(request.value);
    if (!id) { message('رقم الطلب غير صحيح. انسخي الرقم كاملًا من رسالة المشترك.', true); request.focus(); return; }
    const operation = epoch;
    const key = signingKey;
    signing = true;
    issueButton.disabled = true;
    request.readOnly = true;
    try {
      const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, AtomicActivation.payload(id));
      const code = AtomicActivation.token(id, signature);
      if (!await AtomicActivation.verify(code, id, window.ATOMIC_ACTIVATION_PUBLIC_KEY)) throw new Error('Issuer mismatch');
      if (operation !== epoch || !signingKey || expired()) return;
      request.value = AtomicActivation.formatRequest(id);
      output.value = code;
      result.hidden = false;
      message('تم إنشاء الكود لهذا الطلب. انسخيه وأرسليه للمشترك.');
      output.focus(); output.select();
      activity();
    } catch (_) { if (operation === epoch) message('تعذر إنشاء الكود. حاولي مجددًا.', true); }
    finally {
      if (operation === epoch) {
        signing = false;
        issueButton.disabled = false;
        request.readOnly = false;
      }
    }
  });

  byId('copyCode').addEventListener('click', async () => {
    if (expired() || !signingKey || !output.value) return;
    const operation = epoch;
    try {
      await navigator.clipboard.writeText(output.value);
      if (operation === epoch) message('تم نسخ كود التفعيل.');
    } catch (_) {
      if (operation !== epoch) return;
      output.focus(); output.select();
      message('الكود محدد الآن؛ انسخيه من قائمة النسخ في جهازك.');
    }
    activity();
  });

  if (!globalThis.crypto?.subtle || !window.AtomicIssuerCrypto || !window.AtomicActivation || !window.ATOMIC_ISSUER_VAULT || !window.ATOMIC_ACTIVATION_PUBLIC_KEY) {
    unlockButton.disabled = true;
    message('تعذر تجهيز الأداة. افتحي الرابط الآمن في متصفح حديث ثم حدّثي الصفحة.', true);
  } else { message('الأداة مقفلة. أدخلي كلمة المرور للمتابعة.'); }
})();
