/* Offline browser activation. Only a signed code for this stored request unlocks it. */
(() => {
  'use strict';
  const STORAGE_KEY = 'atomic3a-browser-activation-v1';
  const root = document.documentElement;
  const gate = document.getElementById('activationGate');
  const requestField = document.getElementById('activationRequest');
  const codeField = document.getElementById('activationCode');
  const form = document.getElementById('activationForm');
  const copyButton = document.getElementById('activationCopy');
  const submitButton = document.getElementById('activationSubmit');
  const contact = document.getElementById('activationWhatsApp');
  const status = document.getElementById('activationStatus');
  let state;
  let busy = true;
  let storageBlocked = false;
  const api = window.AtomicActivation;

  function message(text, error = false) {
    status.textContent = text;
    status.dataset.error = String(error);
  }

  function controls(enabled) {
    copyButton.disabled = !enabled;
    submitButton.disabled = !enabled;
    codeField.disabled = !enabled;
    contact.setAttribute('aria-disabled', String(!enabled));
    contact.tabIndex = enabled ? 0 : -1;
  }

  function persist(next) {
    const serialized = JSON.stringify(next);
    localStorage.setItem(STORAGE_KEY, serialized);
    if (localStorage.getItem(STORAGE_KEY) !== serialized) throw new Error('Storage unavailable');
    state = next;
  }

  function storageFailure() {
    storageBlocked = true;
    root.dataset.activation = 'locked';
    gate.hidden = false;
    controls(false);
    message('تعذر حفظ التفعيل في هذا المتصفح. افتحي الرابط في متصفح عادي واسمحي بحفظ بيانات الموقع، ثم حدّثي الصفحة.', true);
  }

  function unlock() {
    root.dataset.activation = 'active';
    gate.hidden = true;
    if (typeof window.route === 'function') window.route();
    document.dispatchEvent(new Event('atomic:activated'));
    if (!document.getElementById('rightsDialog').open) document.getElementById('nHome').focus();
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !state) return;
    busy = true;
    controls(false);
    message('جارٍ التحقق من كود التفعيل…');
    try {
      const parsed = api.parseToken(codeField.value);
      if (!parsed) { message('كود التفعيل غير صحيح. انسخي الكود كاملًا من الرسالة وحاولي مجددًا.', true); return; }
      if (parsed.request !== state.request) { message('هذا الكود لطلب آخر. أرسلي رقم الطلب الظاهر هنا للحصول على كود لهذا المتصفح.', true); return; }
      if (!await api.verify(parsed.text, state.request, window.ATOMIC_ACTIVATION_PUBLIC_KEY)) {
        message('تعذر التحقق من الكود. تأكدي من نسخه كاملًا أو تواصلي مع صاحبة المنصة.', true); return;
      }
      try {
        const current = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
        if (!current || current.request !== state.request) { location.reload(); return; }
        persist({ request: state.request, token: parsed.text });
      } catch (_) { storageFailure(); return; }
      message('تم تفعيل المنصة لهذا المتصفح.');
      codeField.value = '';
      unlock();
    } catch (_) { message('تعذر التحقق الآن. حدّثي الصفحة وحاولي مجددًا.', true); }
    finally {
      busy = false;
      if (!gate.hidden && state && !storageBlocked) {
        controls(true);
        codeField.focus();
      }
    }
  });

  copyButton.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(requestField.value); message('تم نسخ رقم الطلب. أرسليه لصاحبة المنصة على واتساب.'); }
    catch (_) { requestField.focus(); requestField.select(); message('رقم الطلب محدد الآن؛ انسخيه من قائمة النسخ في جهازك.'); }
  });

  contact.addEventListener('click', event => {
    if (contact.getAttribute('aria-disabled') === 'true') event.preventDefault();
  });

  window.addEventListener('storage', event => {
    if (event.key === STORAGE_KEY || event.key === null) location.reload();
  });

  async function initialize() {
    controls(false);
    if (!api || !window.ATOMIC_ACTIVATION_PUBLIC_KEY) {
      message('تعذر تحميل شاشة التفعيل. تأكدي من الاتصال بالإنترنت ثم حدّثي الصفحة.', true); return;
    }
    if (!globalThis.crypto?.subtle) {
      message('افتحي رابط المنصة الآمن في إصدار حديث من Chrome أو Safari أو Edge لتفعيل الدخول.', true); return;
    }
    try {
      let stored;
      const raw = localStorage.getItem(STORAGE_KEY);
      try { stored = raw ? JSON.parse(raw) : null; } catch (_) { stored = null; }
      const request = stored && api.normalizeRequest(stored.request);
      persist({ request: request || api.newRequest(), token: request && typeof stored.token === 'string' ? stored.token : null });
    } catch (_) { storageFailure(); return; }
    requestField.value = api.formatRequest(state.request);
    const whatsappMessage = 'السلام عليكم، أرغب في تفعيل منصة نادي أتومك لهذا المتصفح.\nرقم الطلب: ' + requestField.value;
    contact.href = 'https://wa.me/96895823294?text=' + encodeURIComponent(whatsappMessage);
    if (state.token) {
      try {
        if (await api.verify(state.token, state.request, window.ATOMIC_ACTIVATION_PUBLIC_KEY)) { busy = false; unlock(); return; }
        persist({ request: state.request, token: null });
        message('التفعيل المحفوظ غير صالح. أدخلي كود هذا الطلب مجددًا أو تواصلي مع صاحبة المنصة.', true);
      } catch (_) {
        message('تعذر التحقق من التفعيل المحفوظ. حدّثي الصفحة وحاولي مجددًا.', true);
      }
    } else { message('رقم الطلب جاهز. أرسليه على واتساب للحصول على كود التفعيل.'); }
    busy = false;
    controls(true);
  }

  initialize();
})();
