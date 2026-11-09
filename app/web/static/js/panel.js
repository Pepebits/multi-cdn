// Diálogos, confirmaciones escritas, tema y refresco del registro de tareas.
document.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', () => document.getElementById(b.dataset.open).showModal()));
document.querySelectorAll('dialog [data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
document.querySelectorAll('input[data-expected]').forEach(i => i.addEventListener('input', () => {
  i.form.querySelector('[data-submit]').disabled = i.value.trim() !== i.dataset.expected;
}));
(() => {
  const buttons = document.querySelectorAll('[data-theme-choice]');
  if (!buttons.length) return;
  const render = (current) => buttons.forEach(b => b.setAttribute('aria-pressed', String(b.dataset.themeChoice === current)));
  buttons.forEach(b => b.addEventListener('click', () => {
    const choice = b.dataset.themeChoice;
    if (choice === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = choice;
    try { choice === 'auto' ? localStorage.removeItem('multicdn-theme') : localStorage.setItem('multicdn-theme', choice); } catch (e) {}
    render(choice);
  }));
  render(document.documentElement.dataset.theme || 'auto');
})();
if (document.querySelector('.joblog[data-running]')) setTimeout(() => location.reload(), 3000);

// Actualización automática: consulta /api/estado cada 5 s y recarga solo si hay cambios.
(() => {
  const body = document.body;
  const current = body.dataset.stateVersion;
  const toggle = document.getElementById('autorefresh');
  const toast = document.getElementById('update-toast');
  if (!current || !toggle) return;
  const KEY = 'multicdn-autorefresh', SCROLL = 'multicdn-scroll';
  let enabled = true;
  try { enabled = localStorage.getItem(KEY) !== 'off'; } catch (e) {}
  const render = () => toggle.setAttribute('aria-pressed', String(enabled));
  toggle.addEventListener('click', () => {
    enabled = !enabled;
    try { localStorage.setItem(KEY, enabled ? 'on' : 'off'); } catch (e) {}
    render();
  });
  render();
  try { const y = sessionStorage.getItem(SCROLL); if (y) { sessionStorage.removeItem(SCROLL); window.scrollTo(0, +y); } } catch (e) {}
  const reload = () => { try { sessionStorage.setItem(SCROLL, String(window.scrollY)); } catch (e) {} location.reload(); };
  document.getElementById('update-now').addEventListener('click', reload);
  const busy = () => document.querySelector('dialog[open]') ||
    (document.activeElement && document.activeElement.matches('input, select, textarea'));
  setInterval(async () => {
    if (!enabled || document.hidden) return;
    try {
      const r = await fetch('/api/estado', { headers: { Accept: 'application/json' }, cache: 'no-store' });
      if (r.status === 401) { location.href = '/login?next=' + encodeURIComponent(location.pathname); return; }
      const data = await r.json();
      if (data.version === current) return;
      if (busy()) { toast.hidden = false; } else { reload(); }
    } catch (e) { /* sin red: se reintenta en el siguiente ciclo */ }
  }, 5000);
})();

// Añadir credencial: el ejemplo de nombre y las ayudas dependen del proveedor elegido.
(() => {
  const select = document.getElementById('provider');
  const label = document.getElementById('label');
  if (!select || !label || !document.querySelector('[data-provider-help]')) return;
  const render = () => {
    const option = select.selectedOptions[0];
    label.placeholder = option.dataset.placeholder || '';
    document.querySelectorAll('[data-provider-help]').forEach(el => { el.hidden = el.dataset.providerHelp !== select.value; });
  };
  select.addEventListener('change', render);
  render();  // el navegador puede restaurar la selección al volver atrás
})();

// Gráficas: tooltip al pasar el ratón o al enfocar con el teclado; línea vertical en las series.
(() => {
  const tip = document.querySelector('.chart-tip');
  if (!tip) return;
  const show = (el, x, y) => {
    tip.textContent = el.dataset.tip;  // texto, nunca HTML
    tip.hidden = false;
    const r = tip.getBoundingClientRect();
    const left = Math.min(x + 14, window.innerWidth - r.width - 8);
    const top = y - r.height - 12 < 8 ? y + 18 : y - r.height - 12;
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${top}px`;
    const svg = el.ownerSVGElement;
    const cross = svg && svg.querySelector('.c-cross');
    if (cross && el.dataset.cx) {
      cross.setAttribute('x1', el.dataset.cx); cross.setAttribute('x2', el.dataset.cx); cross.classList.add('is-on');
    }
  };
  const hide = (el) => {
    tip.hidden = true;
    const cross = el.ownerSVGElement && el.ownerSVGElement.querySelector('.c-cross');
    if (cross) cross.classList.remove('is-on');
  };
  document.querySelectorAll('[data-chart] [data-tip]').forEach(el => {
    el.addEventListener('pointermove', e => show(el, e.clientX, e.clientY));
    el.addEventListener('pointerleave', () => hide(el));
    el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); show(el, r.left + r.width / 2, r.top); });
    el.addEventListener('blur', () => hide(el));
  });
})();

// En pantallas estrechas las gráficas se desplazan dentro de su tarjeta: empezar por lo más reciente.
document.querySelectorAll('.viz__frame').forEach(f => { f.scrollLeft = f.scrollWidth; });
