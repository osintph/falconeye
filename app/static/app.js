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

// Load stats badge on startup
async function loadStats() {
  try {
    const r = await fetch('/api/scamtext/stats');
    const data = await r.json();
    document.getElementById('stats-badge').textContent = `${data.total} scam messages archived`;
  } catch {}
}
loadStats();

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

// Repository search
async function loadRepo() {
  const q = document.getElementById('repo-search').value.trim();
  const brand = document.getElementById('repo-brand').value;
  const resultsEl = document.getElementById('repo-results');

  resultsEl.innerHTML = '<p class="text-gray-400 text-sm">Loading...</p>';

  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (brand) params.set('brand', brand);
  params.set('limit', '50');

  try {
    const res = await fetch(`/api/scamtext/search?${params}`);
    const data = await res.json();

    if (data.length === 0) {
      resultsEl.innerHTML = '<p class="text-gray-500 text-sm">No results found.</p>';
      return;
    }

    resultsEl.innerHTML = data.map(row => `
      <div class="scam-card">
        <div class="flex items-center justify-between mb-2">
          <span class="brand-badge">${row.brand_tag}</span>
          <span class="text-xs text-gray-500">${row.date_reported ? row.date_reported.split('T')[0] : ''}</span>
        </div>
        ${row.sender_id ? `<p class="text-xs text-gray-400 mb-1">Sender: ${row.sender_id}</p>` : ''}
        <p class="text-sm text-gray-200 mb-2 leading-relaxed">${row.message_content}</p>
        ${row.extracted_url ? `
          <div class="mt-2 flex items-center gap-2">
            <span class="text-xs text-gray-500">Extracted URL:</span>
            <span class="text-xs text-amber-400 break-all">${row.extracted_url}</span>
            <button class="text-xs bg-gray-700 px-2 py-1 rounded hover:bg-gray-600"
              onclick="scanExtractedUrl('${row.extracted_url}')">Scan</button>
          </div>` : ''}
      </div>`).join('');
  } catch (e) {
    resultsEl.innerHTML = `<p class="text-red-400 text-sm">Load failed: ${e.message}</p>`;
  }
}

document.getElementById('repo-search-btn').addEventListener('click', loadRepo);
document.getElementById('tab-repository') && loadRepo();

// Auto-scan from repository
function scanExtractedUrl(url) {
  document.getElementById('scan-url').value = url;
  document.querySelector('[data-tab="scanner"]').click();
  document.getElementById('scan-btn').click();
}

// Submit
document.getElementById('submit-btn').addEventListener('click', async () => {
  const brand = document.getElementById('submit-brand').value;
  const sender = document.getElementById('submit-sender').value.trim();
  const message = document.getElementById('submit-message').value.trim();
  const resultEl = document.getElementById('submit-result');

  if (!brand || !message) {
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Brand and message are required.</p>';
    resultEl.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch('/api/scamtext/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand_tag: brand, sender_id: sender || null, message_content: message }),
    });

    const data = await res.json();

    if (res.status === 409) {
      resultEl.innerHTML = '<p class="text-yellow-400 text-sm">This message is already in the repository.</p>';
    } else if (res.status === 429) {
      resultEl.innerHTML = '<p class="text-red-400 text-sm">Rate limit reached. Wait a minute.</p>';
    } else if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${data.detail}</p>`;
    } else {
      resultEl.innerHTML = `<p class="text-green-400 text-sm">Submitted. SHA-256: ${data.sha256}</p>`;
      document.getElementById('submit-message').value = '';
    }

    resultEl.classList.remove('hidden');
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Submit failed: ${e.message}</p>`;
    resultEl.classList.remove('hidden');
  }
});

// Load repository on tab click
document.querySelector('[data-tab="repository"]').addEventListener('click', loadRepo);
