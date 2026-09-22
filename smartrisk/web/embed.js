(() => {
  const script = document.currentScript;
  if (!script) return;

  function mount(container) {
    if (!container || container.dataset.smartriskMounted === '1') return;
    container.dataset.smartriskMounted = '1';

    const src = new URL('/embed/scanner', script.src);
    const theme = container.dataset.theme || 'dark';
    const compact = container.dataset.compact === '1' ? '1' : '0';
    const appKey = container.dataset.app || container.dataset.appKey || '';
    src.searchParams.set('theme', theme);
    src.searchParams.set('compact', compact);
    if (appKey) { src.searchParams.set('app', appKey); src.searchParams.set('origin', window.location.origin); }

    const iframe = document.createElement('iframe');
    iframe.src = src.toString();
    iframe.title = 'SmartRisk contract risk scanner';
    iframe.loading = 'lazy';
    iframe.style.width = '100%';
    iframe.style.minHeight = container.dataset.height || '430px';
    iframe.style.height = container.dataset.height || '430px';
    iframe.style.border = '0';
    iframe.style.display = 'block';
    iframe.setAttribute('allowtransparency', 'true');

    container.replaceChildren(iframe);
  }

  document.querySelectorAll('[data-smartrisk-widget]').forEach(mount);

  window.addEventListener('message', event => {
    if (!event.data || event.data.type !== 'smartrisk:resize') return;
    document.querySelectorAll('[data-smartrisk-widget] iframe').forEach(frame => {
      if (event.source === frame.contentWindow && Number.isFinite(Number(event.data.height))) {
        frame.style.height = `${Math.max(380, Number(event.data.height))}px`;
      }
    });
  });
})();
