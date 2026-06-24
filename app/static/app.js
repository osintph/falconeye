// Tab navigation
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => {
      b.classList.remove('border-amber-400', 'text-amber-400');
      b.classList.add('border-transparent', 'text-gray-400');
    });
    btn.classList.add('border-amber-400', 'text-amber-400');
    btn.classList.remove('border-transparent', 'text-gray-400');
    document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
    document.getElementById(`tab-${btn.dataset.tab}`).classList.remove('hidden');
  });
});

// Feed status badge on load
async function loadFeedMeta() {
  try {
    const r = await fetch('/api/feeds/status');
    const data = await r.json();
    const meta = document.getElementById('feed-meta');
    if (meta) {
      meta.textContent = `${data.total} entries indexed · ${data.live} live · Sources: ${data.by_source.map(s => `${s.ingest_source} (${s.n})`).join(', ')}`;
    }
    const badge = document.getElementById('stats-badge');
    if (badge) badge.textContent = `${data.total} phishing entries indexed`;
  } catch {}
}
loadFeedMeta();

// Scanner
document.getElementById('scan-btn').addEventListener('click', async () => {
  const url = document.getElementById('scan-url').value.trim();
  const html = document.getElementById('scan-html').value.trim();
  const resultEl = document.getElementById('scan-result');

  if (!url && !html) {
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Provide a URL or HTML source.</p>';
    resultEl.classList.remove('hidden');
    return;
  }

  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Scanning...</p>';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch('/api/scanner/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url || null, raw_html: html || null }),
    });

    if (res.status === 429) {
      resultEl.innerHTML = '<p class="text-red-400 text-sm">Rate limit reached. Wait a minute and try again.</p>';
      return;
    }

    const data = await res.json();

    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${data.detail}</p>`;
      return;
    }

    const liveLabel = data.is_live
      ? '<span class="text-green-400 font-bold">LIVE</span>'
      : '<span class="text-gray-500">OFFLINE</span>';

    const indicatorsHtml = data.indicators.length > 0
      ? data.indicators.map(i => `
          <div class="indicator-hit">
            <span class="text-amber-400 font-bold">[HIT]</span> ${i.description}
            <br/><span class="text-gray-500 text-xs">Pattern: ${i.pattern}</span>
          </div>`).join('')
      : '<p class="indicator-clean text-sm">No known indicators matched.</p>';

    const telegramHtml = data.telegram_bot_id
      ? `<p class="text-sm mt-2">Telegram Bot Token: <span class="text-red-400 font-bold">${data.telegram_bot_id}</span></p>`
      : '';

    const fetchErrorHtml = data.fetch_error
      ? `<p class="text-yellow-500 text-xs mt-2">${data.fetch_error}</p>`
      : '';

    resultEl.innerHTML = `
      <div class="scam-card">
        <div class="flex items-center justify-between mb-4">
          <div>
            <span class="brand-badge">${data.target_brand}</span>
            <span class="ml-3 text-xs text-gray-400">${data.url || 'Raw HTML input'}</span>
          </div>
          <div>${liveLabel}</div>
        </div>
        <p class="text-xs text-gray-400 mb-3 uppercase tracking-wide">Indicators: ${data.indicators_matched} matched</p>
        ${indicatorsHtml}
        ${telegramHtml}
        ${fetchErrorHtml}
      </div>`;
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
});

// PH Phishing Feed
async function loadRepo() {
  const brand = document.getElementById('repo-brand').value;
  const source = document.getElementById('repo-source').value;
  const liveOnly = document.getElementById('repo-live-only').checked;
  const resultsEl = document.getElementById('repo-results');

  resultsEl.innerHTML = '<p class="text-gray-400 text-sm">Loading...</p>';

  const params = new URLSearchParams();
  if (brand) params.set('brand', brand);
  if (source) params.set('source', source);
  if (liveOnly) params.set('live_only', 'true');
  params.set('limit', '50');

  try {
    const res = await fetch(`/api/feeds/search?${params}`);
    const data = await res.json();

    if (data.length === 0) {
      resultsEl.innerHTML = '<p class="text-gray-500 text-sm">No results. Try removing filters or wait for the next ingest cycle.</p>';
      return;
    }

    resultsEl.innerHTML = data.map(row => {
      const indicators = (() => {
        try { return JSON.parse(row.kit_indicators || '[]'); } catch { return []; }
      })();
      const indicatorBadge = indicators.length > 0
        ? `<span class="ml-2 text-xs text-red-400 font-bold">${indicators.length} indicator${indicators.length > 1 ? 's' : ''} matched</span>`
        : '';
      return `
        <div class="scam-card">
          <div class="flex items-center justify-between mb-2 flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <span class="brand-badge">${row.target_brand}</span>
              <span class="text-xs text-gray-500">${row.ingest_source}</span>
              ${row.is_live ? '<span class="text-xs text-green-400 font-bold">LIVE</span>' : '<span class="text-xs text-gray-600">OFFLINE</span>'}
              ${indicatorBadge}
            </div>
            <span class="text-xs text-gray-600">${row.date_scanned ? row.date_scanned.split('T')[0] : ''}</span>
          </div>
          <p class="text-xs text-amber-300 break-all mb-2">${row.phishing_url}</p>
          <button class="text-xs bg-gray-700 px-3 py-1 rounded hover:bg-gray-600"
            onclick="scanExtractedUrl('${row.phishing_url.replace(/'/g, "\\'")}')">
            Scan this URL
          </button>
        </div>`;
    }).join('');
  } catch (e) {
    resultsEl.innerHTML = `<p class="text-red-400 text-sm">Load failed: ${e.message}</p>`;
  }
}

document.getElementById('repo-search-btn').addEventListener('click', loadRepo);
document.querySelector('[data-tab="repository"]').addEventListener('click', () => {
  loadFeedMeta();
  loadRepo();
});

// Auto-scan from feed
function scanExtractedUrl(url) {
  document.getElementById('scan-url').value = url;
  document.querySelector('[data-tab="scanner"]').click();
  document.getElementById('scan-btn').click();
}
