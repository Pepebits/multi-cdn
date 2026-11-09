// Aplica el tema guardado antes de pintar, para evitar el destello.
try { const t = localStorage.getItem('multicdn-theme'); if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t; } catch (e) {}
