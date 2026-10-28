/* Navigation only. All charts and statistics are rendered from stored events. */
(() => {
  const toggle = document.querySelector('[data-nav-toggle]');
  const close = document.querySelector('[data-nav-close]');
  const sidebar = document.querySelector('.sidebar');
  const setOpen = open => {
    document.body.classList.toggle('is-nav-open', open);
    toggle?.setAttribute('aria-expanded', String(open));
    if (sidebar) sidebar.inert = window.innerWidth <= 1100 && !open;
    if (open) document.querySelector('.sidebar .active')?.focus();
  };
  toggle?.addEventListener('click', () => setOpen(!document.body.classList.contains('is-nav-open')));
  close?.addEventListener('click', () => setOpen(false));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && document.body.classList.contains('is-nav-open')) {
      setOpen(false);
      toggle?.focus();
    }
  });
  window.addEventListener('resize', () => {
    setOpen(window.innerWidth <= 1100 && document.body.classList.contains('is-nav-open'));
  });
  setOpen(false);
})();
