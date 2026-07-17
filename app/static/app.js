// ---- Hash-based tab routing ----
// Tab name <-> URL hash <-> visible tab content
// Browser back/forward buttons walk through the hash history natively.

const VALID_TABS = ['home', 'crypto', 'scanner', 'domain', 'telegram', 'ip', 'sandbox', 'url', 'qr', 'image', 'email', 'dorks', 'decoder', 'prospect', 'contact', 'news'];
const DEFAULT_TAB = 'home';

function showTab(tabName) {
  if (!VALID_TABS.includes(tabName)) {
    tabName = DEFAULT_TAB;
  }

  document.querySelectorAll('.tab-content').forEach(el => {
    el.classList.add('hidden');
  });

  const targetContent = document.getElementById(`tab-${tabName}`);
  if (targetContent) {
    targetContent.classList.remove('hidden');
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.dataset.tab === tabName) {
      btn.classList.remove('border-transparent', 'text-gray-400');
      btn.classList.add('border-amber-400', 'text-amber-400');
    } else {
      btn.classList.remove('border-amber-400', 'text-amber-400');
      btn.classList.add('border-transparent', 'text-gray-400');
    }
  });

  // Scroll to top so a user who scrolled down on a long result doesn't land mid-page on the next tab
  window.scrollTo({ top: 0, behavior: 'instant' });

  if (tabName === 'news') loadNews(currentNewsCategory);
}

function getTabFromHash() {
  const hash = window.location.hash.replace(/^#/, '').toLowerCase().trim();
  return hash || DEFAULT_TAB;
}

// Tab button clicks: update the hash. The hashchange event handler renders the tab.
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    const tabName = btn.dataset.tab;
    if (!tabName) return;

    if (getTabFromHash() !== tabName) {
      window.location.hash = `#${tabName}`;
      // hashchange listener below will call showTab()
    } else {
      showTab(tabName);
    }
  });
});

// Browser back/forward buttons fire hashchange. So does setting window.location.hash above.
window.addEventListener('hashchange', () => {
  showTab(getTabFromHash());
});

// Initial render on page load: read the hash or default to Home.
showTab(getTabFromHash());

// ---- PHT timezone formatter ----
function fmtPHT(utcString) {
  if (!utcString) return '';
  try {
    let d;
    if (typeof utcString === 'number') {
      d = new Date(utcString);
    } else {
      const s = String(utcString);
      d = new Date(s.includes('T') || s.includes('Z') ? s : s.replace(' ', 'T') + 'Z');
    }
    if (isNaN(d)) return String(utcString).slice(0, 16);
    return d.toLocaleString('en-PH', {
      timeZone: 'Asia/Manila',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).replace(',', '');
  } catch {
    return String(utcString).slice(0, 16);
  }
}

// ---- Crypto Workbench ----
document.getElementById('crypto-btn').addEventListener('click', runCryptoLookup);
document.getElementById('crypto-address').addEventListener('keydown', e => {
  if (e.key === 'Enter') runCryptoLookup();
});

async function runCryptoLookup() {
  const address = document.getElementById('crypto-address').value.trim();
  const resultEl = document.getElementById('crypto-result');
  const summaryEl = document.getElementById('crypto-summary');
  const timelineEl = document.getElementById('crypto-timeline');
  const graphEl = document.getElementById('crypto-graph');

  if (!address) return;

  summaryEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Fetching blockchain data...</p>';
  timelineEl.innerHTML = '';
  graphEl.innerHTML = '';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/crypto/lookup/${encodeURIComponent(address)}`);
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      summaryEl.innerHTML = `<p class="text-red-400 text-sm">Unexpected response from server (HTTP ${res.status}). If this persists, the API may be rate-limited.</p>`;
      return;
    }
    const data = await res.json();

    if (!res.ok) {
      summaryEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${data.detail}</p>`;
      return;
    }

    renderCryptoSummary(summaryEl, data);
    renderTimeline(timelineEl, data);
    renderGraph(graphEl, data, address);

  } catch (e) {
    summaryEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
}

function renderCryptoSummary(el, data) {
  const chain = data.chain;
  let balanceStr = '';
  if (chain === 'BTC') balanceStr = `${data.balance_btc} BTC`;
  else if (chain === 'ETH') balanceStr = `${data.balance_eth} ETH`;
  else if (chain === 'USDT-TRC20') balanceStr = `${data.usdt_balance} USDT`;

  el.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center gap-3 mb-4">
        <span class="brand-badge text-sm px-3 py-1">${chain}</span>
        <span class="text-xs text-gray-400 break-all">${data.address}</span>
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Balance</p>
          <p class="text-amber-400 font-bold">${balanceStr}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Transactions</p>
          <p class="text-white font-bold">${data.tx_count}</p>
        </div>
        ${data.received_btc !== undefined ? `
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Total Received</p>
          <p class="text-green-400 font-bold">${data.received_btc} BTC</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Total Sent</p>
          <p class="text-red-400 font-bold">${data.spent_btc} BTC</p>
        </div>` : ''}
        ${data.first_seen ? `
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">First Seen (PHT)</p>
          <p class="text-gray-300 text-xs">${fmtPHT(data.first_seen)}</p>
        </div>` : ''}
      </div>
    </div>`;
}

function renderTimeline(el, data) {
  const txs = data.transactions || [];
  if (txs.length === 0) {
    el.innerHTML = '<p class="text-gray-500 text-sm">No transactions found.</p>';
    return;
  }

  el.innerHTML = txs.map(tx => {
    const isIn = tx.is_received;
    const dirClass = isIn ? 'tx-in' : 'tx-out';
    const dirLabel = isIn
      ? '<span class="text-green-400 font-bold">IN</span>'
      : '<span class="text-red-400 font-bold">OUT</span>';

    let amountStr = '';
    if (tx.balance_change !== undefined) {
      amountStr = `${(tx.balance_change / 1e8).toFixed(8)} BTC`;
    } else if (tx.value_eth !== undefined) {
      amountStr = `${tx.value_eth} ETH`;
    } else if (tx.amount_usdt !== undefined) {
      amountStr = `${tx.amount_usdt} USDT`;
    }

    const timeStr = fmtPHT(tx.time);

    const counterparty = tx.from || tx.sender || tx.recipient || '';
    const shortCounterparty = counterparty ? counterparty.slice(0, 16) + '...' : '';

    return `
      <div class="tx-row ${dirClass}">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            ${dirLabel}
            <span class="text-amber-300 font-bold">${amountStr}</span>
            ${shortCounterparty ? `<span class="text-gray-500 text-xs">${isIn ? 'from' : 'to'} ${shortCounterparty}</span>` : ''}
          </div>
          <span class="text-gray-600 text-xs">${timeStr}</span>
        </div>
        <p class="text-gray-600 text-xs mt-1 truncate">${tx.hash || ''}</p>
      </div>`;
  }).join('');
}

function renderGraph(container, data, targetAddress) {
  const txs = data.transactions || [];
  if (txs.length === 0) {
    container.innerHTML = '<p class="text-gray-500 text-sm p-4">No transactions to graph.</p>';
    return;
  }

  const nodeMap = new Map();
  const links = [];

  const addNode = (id, type) => {
    if (!nodeMap.has(id)) {
      nodeMap.set(id, { id, type, short: id.slice(0, 8) + '...' });
    }
  };

  addNode(targetAddress, 'target');

  txs.slice(0, 30).forEach(tx => {
    const counterparty = tx.from || tx.sender || tx.to || tx.recipient;
    if (!counterparty || counterparty === targetAddress) return;
    addNode(counterparty, 'counterparty');
    links.push({
      source: tx.is_received ? counterparty : targetAddress,
      target: tx.is_received ? targetAddress : counterparty,
      amount: tx.balance_change || tx.value_eth || tx.amount_usdt || 0,
    });
  });

  const nodes = Array.from(nodeMap.values());
  const width = container.clientWidth || 800;
  const height = 400;

  container.innerHTML = '';
  const svg = d3.select(container)
    .append('svg')
    .attr('viewBox', `0 0 ${width} ${height}`);

  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(30));

  svg.append('defs').append('marker')
    .attr('id', 'arrow')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 20)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-5L10,0L0,5')
    .attr('fill', '#4b5563');

  const link = svg.append('g')
    .selectAll('line')
    .data(links)
    .join('line')
    .attr('class', 'link')
    .attr('marker-end', 'url(#arrow)');

  const node = svg.append('g')
    .selectAll('g')
    .data(nodes)
    .join('g')
    .attr('class', d => `node ${d.type}`)
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    );

  node.append('circle')
    .attr('r', d => d.type === 'target' ? 14 : 8)
    .attr('fill', d => d.type === 'target' ? '#fbbf24' : d.type === 'exchange' ? '#60a5fa' : '#374151');

  node.append('text')
    .attr('x', 0)
    .attr('y', d => d.type === 'target' ? 26 : 20)
    .attr('text-anchor', 'middle')
    .text(d => d.short);

  node.append('title').text(d => d.id);

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });
}

// ---- Phishing Scanner ----
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

    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${data.detail}</p>`;
      return;
    }

    const liveLabel = data.is_live
      ? '<span class="text-green-400 font-bold">LIVE</span>'
      : '<span class="text-gray-500">OFFLINE / TIMED OUT</span>';

    const indicatorsHtml = data.indicators.length > 0
      ? data.indicators.map(i => `
          <div class="indicator-hit">
            <span class="text-amber-400 font-bold">[HIT]</span> ${i.description}
            <br/><span class="text-gray-500 text-xs">Pattern: ${i.pattern}</span>
          </div>`).join('')
      : '<p class="text-green-400 text-sm">No known indicators matched.</p>';

    resultEl.innerHTML = `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <div class="flex items-center justify-between mb-4">
          <div class="flex items-center gap-3">
            <span class="brand-badge">${data.target_brand}</span>
            <span class="text-xs text-gray-400 break-all">${data.url || 'Raw HTML'}</span>
          </div>
          ${liveLabel}
        </div>
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-3">Indicators: ${data.indicators_matched} matched</p>
        ${indicatorsHtml}
        ${data.telegram_bot_id ? `<p class="text-sm mt-3">Telegram Bot Token: <span class="text-red-400 font-bold">${data.telegram_bot_id}</span></p>` : ''}
        ${data.fetch_error ? `<p class="text-yellow-500 text-xs mt-3">${data.fetch_error}</p>` : ''}
      </div>`;
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
});

// ---- URL Expander ----
function urlStatusClass(status) {
  if (status >= 200 && status < 300) return 'text-green-400';
  if (status >= 300 && status < 400) return 'text-amber-400';
  if (status >= 400) return 'text-red-400';
  return 'text-gray-500';
}

document.getElementById('url-btn').addEventListener('click', runUrlExpand);
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runUrlExpand();
});

async function runUrlExpand() {
  const url = document.getElementById('url-input').value.trim();
  const resultEl = document.getElementById('url-result');
  if (!url) {
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Enter a URL to expand.</p>';
    resultEl.classList.remove('hidden');
    return;
  }
  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Following redirects...</p>';
  resultEl.classList.remove('hidden');
  try {
    const res = await fetch('/api/url/expand', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${escapeHtml(String(data.detail || 'request failed'))}</p>`;
      return;
    }
    renderUrlExpand(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${escapeHtml(e.message)}</p>`;
  }
}

function renderUrlExpand(el, data) {
  const s = data.signals || {};
  const pills = [
    `<span class="inline-block text-xs bg-gray-800 px-2 py-1 rounded text-gray-300">shortener depth: ${Number(s.shortener_chain_depth) || 0}</span>`,
    `<span class="inline-block text-xs bg-gray-800 px-2 py-1 rounded text-gray-300">TLD switches: ${Number(s.tld_switches) || 0}</span>`,
    s.final_tld ? `<span class="inline-block text-xs bg-gray-800 px-2 py-1 rounded text-gray-300">final TLD: .${escapeHtml(s.final_tld)}</span>` : '',
    s.final_is_punycode ? `<span class="inline-block text-xs bg-red-900 px-2 py-1 rounded text-red-300">&#9888; punycode hostname</span>` : '',
    s.suspicious_ports ? `<span class="inline-block text-xs bg-red-900 px-2 py-1 rounded text-red-300">&#9888; non-standard port</span>` : '',
  ].filter(Boolean).join(' ');

  const blockedBanner = data.blocked_at_hop
    ? `<div class="bg-red-950 border border-red-800 rounded p-4 text-sm text-red-300">
         &#9940; Chain blocked at hop ${data.blocked_at_hop}: ${escapeHtml(String(data.blocked_reason || 'unsafe target'))}
       </div>`
    : '';

  const hopsHtml = (data.chain || []).map(hop => {
    const statusCls = urlStatusClass(hop.status);
    const tls = hop.tls
      ? `<div class="text-xs text-gray-500 mt-1">TLS issuer: ${escapeHtml(String(hop.tls.issuer || 'unknown'))}${hop.tls.valid_to ? ' &middot; valid to ' + escapeHtml(String(hop.tls.valid_to)) : ''}</div>`
      : '';
    const loc = hop.location
      ? `<div class="text-xs text-amber-300 mt-1 break-all">&#8594; ${escapeHtml(String(hop.location))}</div>`
      : '';
    const err = hop.error
      ? `<div class="text-xs text-red-400 mt-1">${escapeHtml(String(hop.error))}</div>`
      : '';
    const statusLabel = hop.status ? hop.status : '&mdash;';
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-3">
        <div class="flex items-center gap-3">
          <span class="text-xs text-gray-500 font-mono">#${hop.hop}</span>
          <span class="text-sm font-bold ${statusCls}">${statusLabel}</span>
          <span class="text-xs text-gray-400 break-all font-mono" title="${escapeAttr(String(hop.url || ''))}">${escapeHtml(String(hop.url || ''))}</span>
          <span class="text-xs text-gray-600 ml-auto whitespace-nowrap">${Number(hop.elapsed_ms) || 0} ms</span>
        </div>
        ${hop.server ? `<div class="text-xs text-gray-500 mt-1">server: ${escapeHtml(String(hop.server))}</div>` : ''}
        ${tls}${loc}${err}
      </div>`;
  }).join('');

  const shot = data.screenshot || {};
  const shotHtml = shot.available && shot.data_uri
    ? `<img src="${escapeAttr(shot.data_uri)}" alt="Final page screenshot" class="max-w-full rounded border border-gray-800" />`
    : `<p class="text-xs text-gray-500">${escapeHtml(String(shot.reason || 'Screenshot unavailable'))}</p>`;

  el.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="grid gap-2 mb-4">
        <div class="text-xs text-gray-500 uppercase tracking-wide">Original</div>
        <div class="text-sm text-gray-300 break-all font-mono">${escapeHtml(String(data.original || ''))}</div>
        <div class="text-xs text-gray-500 uppercase tracking-wide mt-2">Final landing URL</div>
        <div class="text-sm text-amber-300 break-all font-mono">${escapeHtml(String(data.final || ''))}</div>
      </div>
      <div class="flex items-center gap-3 flex-wrap">
        <span class="text-xs text-gray-400">${Number(data.hop_count) || 0} hop(s)</span>
        <button id="url-pivot-btn" class="bg-amber-400 text-gray-950 font-bold px-4 py-1.5 rounded text-xs hover:bg-amber-300 transition">Push to Phishing Scanner &#8594;</button>
      </div>
    </div>
    ${pills ? `<div class="flex flex-wrap gap-2">${pills}</div>` : ''}
    ${blockedBanner}
    <div class="space-y-2">${hopsHtml}</div>
    <div class="bg-gray-900 border border-gray-800 rounded p-4">
      <div class="text-xs text-gray-500 uppercase tracking-wide mb-2">Final page screenshot</div>
      ${shotHtml}
    </div>`;

  const pivot = document.getElementById('url-pivot-btn');
  if (pivot && data.final) {
    pivot.addEventListener('click', () => pushToTab('scanner', 'scan-url', 'scan-btn', data.final));
  }
}

// ---- QR Analyzer ----
let qrSelectedFile = null;

const qrDrop = document.getElementById('qr-drop');
const qrFileInput = document.getElementById('qr-file');
qrDrop.addEventListener('click', () => qrFileInput.click());
qrDrop.addEventListener('dragover', e => { e.preventDefault(); qrDrop.classList.add('border-amber-400'); });
qrDrop.addEventListener('dragleave', () => qrDrop.classList.remove('border-amber-400'));
qrDrop.addEventListener('drop', e => {
  e.preventDefault();
  qrDrop.classList.remove('border-amber-400');
  if (e.dataTransfer.files && e.dataTransfer.files[0]) qrSetFile(e.dataTransfer.files[0]);
});
qrFileInput.addEventListener('change', () => {
  if (qrFileInput.files && qrFileInput.files[0]) qrSetFile(qrFileInput.files[0]);
});

function qrSetFile(file) {
  qrSelectedFile = file;
  document.getElementById('qr-datauri').value = '';
  document.getElementById('qr-filename').textContent = `Selected: ${file.name} (${Math.round(file.size / 1024)} KB)`;
}

document.getElementById('qr-btn').addEventListener('click', runQrDecode);
document.getElementById('qr-sample').addEventListener('click', async () => {
  const resultEl = document.getElementById('qr-result');
  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Loading sample...</p>';
  resultEl.classList.remove('hidden');
  try {
    const blob = await (await fetch('/static/samples/qr-example.png')).blob();
    await qrDecodeBlob(blob);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Could not load sample: ${escapeHtml(e.message)}</p>`;
  }
});

async function runQrDecode() {
  const dataUri = document.getElementById('qr-datauri').value.trim();
  const resultEl = document.getElementById('qr-result');
  if (!qrSelectedFile && !dataUri) {
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Choose an image or paste a data URI.</p>';
    resultEl.classList.remove('hidden');
    return;
  }
  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Decoding...</p>';
  resultEl.classList.remove('hidden');
  try {
    let res;
    if (qrSelectedFile) {
      const fd = new FormData();
      fd.append('image', qrSelectedFile);
      res = await fetch('/api/qr/decode', { method: 'POST', body: fd });
    } else {
      res = await fetch('/api/qr/decode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data_uri: dataUri }),
      });
    }
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${escapeHtml(String(data.detail || 'request failed'))}</p>`;
      return;
    }
    renderQr(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${escapeHtml(e.message)}</p>`;
  }
}

async function qrDecodeBlob(blob) {
  const resultEl = document.getElementById('qr-result');
  const fd = new FormData();
  fd.append('image', blob, 'qr-example.png');
  const res = await fetch('/api/qr/decode', { method: 'POST', body: fd });
  const data = await res.json();
  if (!res.ok) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${escapeHtml(String(data.detail || 'request failed'))}</p>`;
    return;
  }
  renderQr(resultEl, data);
}

function renderQr(el, data) {
  if (!data.count) {
    el.innerHTML = `<div class="bg-red-950 border border-red-800 rounded p-4 text-sm text-red-300">${escapeHtml(String(data.error || 'No QR code detected.'))}</div>`;
    return;
  }
  const cards = (data.codes || []).map(code => {
    const badge = `<span class="inline-block text-xs bg-gray-800 px-2 py-1 rounded text-amber-300 uppercase tracking-wide">${escapeHtml(String(code.kind))}</span>`;
    const pivot = code.is_url
      ? `<button class="qr-pivot-btn bg-amber-400 text-gray-950 font-bold px-4 py-1.5 rounded text-xs hover:bg-amber-300 transition mt-3" data-url="${escapeAttr(String(code.data))}">Push to URL Expander &#8594;</button>`
      : '';
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-4">
        <div class="flex items-center gap-3 mb-2">
          <span class="text-xs text-gray-500 font-mono">#${code.index}</span>
          ${badge}
        </div>
        <div class="text-sm text-gray-200 break-all font-mono">${escapeHtml(String(code.data))}</div>
        ${pivot}
      </div>`;
  }).join('');
  el.innerHTML = `<p class="text-xs text-gray-500 uppercase tracking-wide">${data.count} code(s) decoded</p>${cards}`;

  el.querySelectorAll('.qr-pivot-btn').forEach(btn => {
    btn.addEventListener('click', () => pushToTab('url', 'url-input', 'url-btn', btn.dataset.url));
  });
}

// Switch to target tab, prefill its input, and trigger its lookup button.
function pushToTab(tabName, inputId, triggerId, value) {
  showTab(tabName);
  if (window.location.hash !== `#${tabName}`) window.location.hash = tabName;
  const input = document.getElementById(inputId);
  if (input) input.value = value;
  const trigger = document.getElementById(triggerId);
  if (trigger) trigger.click();
}

// ---- News ----
let currentNewsCategory = 'global_cyber';

document.querySelectorAll('.news-cat-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.news-cat-btn').forEach(b => {
      b.classList.remove('active-news', 'bg-amber-400', 'text-gray-950', 'font-bold');
      b.classList.add('bg-gray-800', 'text-gray-300');
    });
    btn.classList.add('active-news', 'bg-amber-400', 'text-gray-950', 'font-bold');
    btn.classList.remove('bg-gray-800', 'text-gray-300');
    currentNewsCategory = btn.dataset.cat;
    loadNews(currentNewsCategory);
  });
});

// ---- Domain Intelligence ----

document.getElementById('domain-btn').addEventListener('click', runDomainLookup);
document.getElementById('domain-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runDomainLookup();
});

async function runDomainLookup() {
  const raw = document.getElementById('domain-input').value.trim();
  const resultEl = document.getElementById('domain-result');

  if (!raw) return;

  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Querying RDAP, DNS, certificate transparency, and ASN sources...</p>';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/domain/lookup/${encodeURIComponent(raw)}`);
    const data = await res.json();

    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${data.detail}</p>`;
      return;
    }

    renderDomainResult(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
}

function renderDomainResult(el, data) {
  const cacheBadge = data.cache_hit
    ? '<span class="text-xs text-gray-500">cached</span>'
    : '<span class="text-xs text-green-400">fresh</span>';

  el.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between">
        <div>
          <span class="brand-badge text-sm px-3 py-1">${data.domain}</span>
          ${data.rdap?.events?.registration ? `<span class="ml-3 text-xs text-gray-400">Registered ${fmtPHT(data.rdap.events.registration)}</span>` : ''}
        </div>
        ${cacheBadge}
      </div>
    </div>
    ${renderRdapCard(data.rdap, data.whois_text)}
    ${renderDnsCard(data.dns)}
    ${renderNetworkCard(data.network)}
    ${renderCtCard(data.ct)}
    ${renderSubdomainsCard(data.ct)}
  `;
}

function renderRdapCard(rdap, whoisText) {
  if (!rdap || rdap.error === 'not_found') {
    if (whoisText) {
      return `
        <div class="bg-gray-900 border border-gray-800 rounded p-5">
          <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Registration (WHOIS fallback)</h3>
          <p class="text-xs text-amber-400 mb-3">RDAP unavailable for this TLD. Falling back to legacy WHOIS.</p>
          <pre class="text-xs text-gray-400 bg-gray-950 p-3 rounded overflow-x-auto max-h-64 whitespace-pre-wrap">${whoisText.replace(/</g, '&lt;')}</pre>
        </div>`;
    }
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Registration</h3>
        <p class="text-sm text-gray-500">Domain not found or no registration data available.</p>
      </div>`;
  }

  const events = rdap.events || {};
  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Registration (RDAP)</h3>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4">
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Registered</p>
          <p class="text-amber-300 text-sm">${fmtPHT(events.registration)}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Expires</p>
          <p class="text-amber-300 text-sm">${fmtPHT(events.expiration)}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Last Changed</p>
          <p class="text-gray-400 text-sm">${fmtPHT(events['last changed'] || events['last update of RDAP database'])}</p>
        </div>
      </div>

      ${rdap.registrar ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Registrar</p>
        <p class="text-sm text-white">${escapeHtml(rdap.registrar.name || rdap.registrar.handle || 'Unknown')}</p>
        ${rdap.registrar.email ? `<p class="text-xs text-gray-400">${escapeHtml(rdap.registrar.email)}</p>` : ''}
      </div>` : ''}

      ${rdap.registrant ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Registrant</p>
        <p class="text-sm text-white">${escapeHtml(rdap.registrant.name || rdap.registrant.handle || 'Redacted (GDPR)')}</p>
        ${rdap.registrant.email ? `<p class="text-xs text-gray-400">${escapeHtml(rdap.registrant.email)}</p>` : ''}
      </div>` : ''}

      ${rdap.abuse_contact ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Abuse Contact</p>
        <p class="text-sm text-white">${escapeHtml(rdap.abuse_contact.email || rdap.abuse_contact.name || 'Not listed')}</p>
      </div>` : ''}

      ${rdap.nameservers && rdap.nameservers.length ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Nameservers</p>
        <div class="flex flex-wrap gap-2">
          ${rdap.nameservers.map(ns => `<span class="text-xs bg-gray-800 px-2 py-1 rounded text-gray-300">${escapeHtml(ns)}</span>`).join('')}
        </div>
      </div>` : ''}

      ${rdap.status && rdap.status.length ? `
      <div>
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">EPP Status</p>
        <div class="flex flex-wrap gap-2">
          ${rdap.status.map(s => `<span class="text-xs bg-gray-800 px-2 py-1 rounded text-amber-300">${escapeHtml(s)}</span>`).join('')}
        </div>
      </div>` : ''}
    </div>`;
}

function renderDnsCard(dns) {
  if (!dns) return '';

  const sections = [];
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA'];
  for (const t of types) {
    const records = dns[t] || [];
    if (records.length === 0) continue;
    sections.push(`
      <div class="mb-3">
        <p class="text-xs text-amber-400 font-bold uppercase tracking-wide mb-1">${t} Records</p>
        ${records.map(r => `<p class="text-xs text-gray-300 font-mono break-all">${r}</p>`).join('')}
      </div>`);
  }

  // Reverse DNS
  const ptrEntries = Object.entries(dns.ptr_records || {});
  if (ptrEntries.length > 0) {
    sections.push(`
      <div class="mb-3">
        <p class="text-xs text-amber-400 font-bold uppercase tracking-wide mb-1">Reverse DNS</p>
        ${ptrEntries.map(([ip, ptrs]) => `
          <p class="text-xs text-gray-300 font-mono">
            <span class="text-gray-500">${ip}</span> → ${ptrs.length ? ptrs.join(', ') : '<span class="text-gray-600">no PTR</span>'}
          </p>`).join('')}
      </div>`);
  }

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">DNS Records</h3>
      ${sections.length ? sections.join('') : '<p class="text-sm text-gray-500">No DNS records returned.</p>'}
    </div>`;
}

function renderNetworkCard(network) {
  if (!network || !network.ips || network.ips.length === 0) return '';

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Network Attribution</h3>
      ${network.ips.map(n => `
        <div class="mb-3 pb-3 border-b border-gray-800 last:border-0 last:pb-0">
          <div class="flex items-center gap-3 mb-2">
            <span class="text-amber-300 font-mono text-sm">${n.ip}</span>
            ${n.prefix ? `<span class="text-xs text-gray-500">${n.prefix}</span>` : ''}
          </div>
          <p class="text-xs text-gray-400">
            <span class="text-gray-500">ASN:</span> AS${n.asn || '?'}
            ${n.asn_holder ? `<span class="text-gray-500 ml-3">Holder:</span> ${n.asn_holder}` : ''}
          </p>
        </div>`).join('')}
    </div>`;
}

function renderCtCard(ct) {
  if (!ct) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Certificate Transparency</h3>
        <p class="text-sm text-gray-500">No data returned.</p>
      </div>`;
  }

  let sourceBadge = '';
  if (ct.source === 'crt.sh') {
    sourceBadge = '<span class="text-xs text-gray-500">via crt.sh</span>';
  } else if (ct.source === 'certspotter') {
    sourceBadge = '<span class="text-xs text-blue-400">via Certspotter (crt.sh fallback)</span>';
  }

  if (ct.error) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Certificate Transparency</h3>
        <div class="bg-yellow-900/20 border border-yellow-700/30 rounded p-3">
          <p class="text-sm text-yellow-400 font-bold mb-1">CT sources unavailable</p>
          <p class="text-xs text-gray-400">${ct.error}</p>
        </div>
      </div>`;
  }

  if (!ct.certificates || ct.certificates.length === 0) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">Certificate Transparency</h3>
          ${sourceBadge}
        </div>
        <p class="text-sm text-gray-500">No certificates found in CT logs for this domain.</p>
      </div>`;
  }

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">Certificate Transparency Timeline</h3>
        ${sourceBadge}
      </div>
      <p class="text-xs text-gray-500 mb-3">${ct.certificates.length} certificate${ct.certificates.length !== 1 ? 's' : ''} found in CT logs (showing latest 25)</p>
      <div class="space-y-2">
        ${ct.certificates.slice(0, 25).map(c => `
          <div class="bg-gray-950 rounded p-3 border border-gray-800">
            <div class="flex items-center justify-between mb-1">
              <p class="text-xs text-amber-300 font-mono">${c.common_name || '(no CN)'}</p>
              <p class="text-xs text-gray-500">${fmtPHT(c.not_before)}</p>
            </div>
            <p class="text-xs text-gray-500 mb-1">Issuer: ${c.issuer && c.issuer.length > 80 ? c.issuer.slice(0, 80) + '...' : (c.issuer || 'Unknown')}</p>
            ${c.sans && c.sans.length > 1 ? `<p class="text-xs text-gray-400">SANs: ${c.sans.slice(0, 10).join(', ')}${c.sans.length > 10 ? ' ...' : ''}</p>` : ''}
          </div>`).join('')}
      </div>
    </div>`;
}

function renderSubdomainsCard(ct) {
  if (!ct || ct.error || !ct.subdomains || ct.subdomains.length === 0) return '';

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Subdomains (from CT logs)</h3>
      <p class="text-xs text-gray-500 mb-3">${ct.subdomains.length} unique subdomain${ct.subdomains.length !== 1 ? 's' : ''} observed</p>
      <div class="flex flex-wrap gap-2">
        ${ct.subdomains.slice(0, 100).map(s => `<span class="text-xs bg-gray-800 px-2 py-1 rounded text-gray-300 font-mono">${s}</span>`).join('')}
      </div>
    </div>`;
}

async function loadNews(category) {
  const el = document.getElementById('news-results');
  el.innerHTML = '<p class="text-gray-400 text-sm animate-pulse col-span-2">Loading feed...</p>';

  try {
    const res = await fetch(`/api/news/${category}`);
    const data = await res.json();

    if (data.length === 0) {
      el.innerHTML = '<p class="text-gray-500 text-sm">No articles found.</p>';
      return;
    }

    el.innerHTML = data.map(item => {
      const safeUrl = /^https?:\/\//i.test(item.url) ? item.url : '#';
      return `
      <a href="${escapeAttr(safeUrl)}" target="_blank" rel="noopener noreferrer" class="news-card block">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-amber-400 font-bold">${escapeHtml(item.feed_source)}</span>
          <span class="text-xs text-gray-600">${fmtPHT(item.published_at)}</span>
        </div>
        <p class="text-sm text-white leading-snug mb-1">${escapeHtml(item.title)}</p>
        ${item.summary ? `<p class="text-xs text-gray-500 leading-relaxed line-clamp-2">${escapeHtml(item.summary)}</p>` : ''}
      </a>`;
    }).join('');
  } catch (e) {
    el.innerHTML = `<p class="text-red-400 text-sm">Load failed: ${e.message}</p>`;
  }
}

// ---- Telegram Channel Inspector ----

document.getElementById('telegram-btn').addEventListener('click', runTelegramLookup);
document.getElementById('telegram-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runTelegramLookup();
});

function normalizeChannelInput(raw) {
  raw = raw.trim();
  if (raw.startsWith('@')) raw = raw.slice(1);
  // Extract name from any t.me URL form (t.me/x, t.me/s/x, https://t.me/x)
  const m = raw.match(/t\.me\/(?:s\/)?([a-zA-Z0-9_]{4,32})/i);
  if (m) return m[1];
  return raw.split('/')[0].split('?')[0].split('#')[0];
}

async function runTelegramLookup() {
  const raw = document.getElementById('telegram-input').value.trim();
  const resultEl = document.getElementById('telegram-result');

  if (!raw) return;

  const channel = normalizeChannelInput(raw);

  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Fetching channel preview from t.me...</p>';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/telegram/lookup/${encodeURIComponent(channel)}`);
    const data = await res.json();

    if (!res.ok) {
      resultEl.innerHTML = `<div class="bg-yellow-900/20 border border-yellow-700/30 rounded p-4">
        <p class="text-yellow-400 text-sm font-bold mb-1">Lookup failed</p>
        <p class="text-xs text-gray-400">${data.detail}</p>
      </div>`;
      return;
    }

    renderTelegramResult(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
}

function renderTelegramResult(el, data) {
  const cacheBadge = data.cache_hit
    ? '<span class="text-xs text-gray-500">cached</span>'
    : '<span class="text-xs text-green-400">fresh</span>';

  el.innerHTML = `
    ${renderTelegramHeader(data, cacheBadge)}
    ${renderTelegramIocs(data.aggregated_iocs)}
    ${renderTelegramMessages(data.messages)}
  `;
}

function renderTelegramHeader(data, cacheBadge) {
  const safePhotoUrl = data.photo_url && /^https:\/\//i.test(data.photo_url) ? data.photo_url : null;
  const photoHtml = safePhotoUrl
    ? `<img src="${escapeAttr(safePhotoUrl)}" class="w-16 h-16 rounded-full border border-gray-700" alt="" onerror="this.style.display='none'" />`
    : `<div class="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center text-amber-400 font-bold text-2xl">${escapeHtml((data.title || '?').charAt(0).toUpperCase())}</div>`;

  const stats = [];
  if (data.subscribers) stats.push(`<span class="text-amber-300 font-bold">${data.subscribers}</span> subscribers`);
  if (data.photos) stats.push(`<span class="text-gray-300">${data.photos}</span> photos`);
  if (data.videos) stats.push(`<span class="text-gray-300">${data.videos}</span> videos`);
  if (data.files) stats.push(`<span class="text-gray-300">${data.files}</span> files`);
  if (data.links) stats.push(`<span class="text-gray-300">${data.links}</span> links`);

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-start justify-between mb-3">
        <div class="flex items-start gap-4">
          ${photoHtml}
          <div>
            <h3 class="text-base font-bold text-white">${escapeHtml(data.title)}</h3>
            <p class="text-xs text-amber-400 mb-2">${escapeHtml(data.username)}</p>
            ${data.description ? `<p class="text-xs text-gray-400 max-w-2xl">${escapeHtml(data.description)}</p>` : ''}
          </div>
        </div>
        ${cacheBadge}
      </div>
      ${stats.length ? `<div class="flex gap-4 text-xs text-gray-400 mt-3 pt-3 border-t border-gray-800">${stats.join(' · ')}</div>` : ''}
    </div>`;
}

function renderTelegramIocs(iocs) {
  if (!iocs) return '';

  const sections = [
    {key: "urls", label: "URLs", color: "amber-300"},
    {key: "crypto_btc", label: "Bitcoin Addresses", color: "yellow-400"},
    {key: "crypto_eth", label: "Ethereum Addresses", color: "blue-400"},
    {key: "crypto_trc20", label: "TRON / USDT TRC20", color: "green-400"},
    {key: "emails", label: "Email Addresses", color: "purple-400"},
    {key: "phones_ph", label: "PH Phone Numbers", color: "amber-300"},
    {key: "phones_intl", label: "International Phones", color: "gray-300"},
    {key: "possible_accounts", label: "Possible Account Numbers", color: "orange-300"},
    {key: "brands", label: "Brands Mentioned", color: "amber-300"},
  ];

  const renderedSections = sections
    .filter(s => iocs[s.key] && iocs[s.key].length > 0)
    .map(s => {
      const items = iocs[s.key].slice(0, 50);
      const isCrypto = s.key.startsWith("crypto_");
      const itemsHtml = items.map(item => {
        if (isCrypto) {
          return `<span class="inline-flex items-center gap-1 bg-gray-800 px-2 py-1 rounded text-xs font-mono">
            <span class="text-gray-200 break-all">${item}</span>
            <button onclick="pivotToCrypto('${item}')" class="text-amber-400 hover:text-amber-300 text-xs font-bold">↗</button>
          </span>`;
        }
        if (s.key === "urls") {
          return `<span class="inline-flex items-center gap-1 bg-gray-800 px-2 py-1 rounded text-xs font-mono">
            <span class="text-gray-200 break-all">${item}</span>
            <button onclick="pivotToScanner('${item.replace(/'/g, "\\'")}')" class="text-amber-400 hover:text-amber-300 text-xs font-bold">↗</button>
          </span>`;
        }
        return `<span class="bg-gray-800 px-2 py-1 rounded text-xs font-mono text-gray-200 break-all">${item}</span>`;
      }).join('');

      return `
        <div class="mb-4">
          <p class="text-xs text-${s.color} font-bold uppercase tracking-wide mb-2">${s.label} (${iocs[s.key].length})</p>
          <div class="flex flex-wrap gap-2">${itemsHtml}</div>
        </div>`;
    });

  if (renderedSections.length === 0) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Aggregated IOCs</h3>
        <p class="text-sm text-gray-500">No IOCs extracted from the visible message preview.</p>
      </div>`;
  }

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-4 uppercase tracking-wide">Aggregated IOCs (across all messages)</h3>
      ${renderedSections.join('')}
    </div>`;
}

function renderTelegramMessages(messages) {
  if (!messages || messages.length === 0) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Recent Messages</h3>
        <p class="text-sm text-gray-500">No messages in the public preview.</p>
      </div>`;
  }

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Recent Messages (${messages.length})</h3>
      <div class="space-y-3">
        ${messages.slice().reverse().map(m => `
          <div class="bg-gray-950 rounded p-3 border border-gray-800">
            <div class="flex items-center justify-between mb-2">
              <div class="flex items-center gap-2">
                <span class="text-xs text-gray-500">${fmtPHT(m.timestamp)}</span>
                ${m.views ? `<span class="text-xs text-gray-600">${m.views} views</span>` : ''}
                ${m.forwarded_from ? `<span class="text-xs text-blue-400">⤴ ${escapeHtml(m.forwarded_from)}</span>` : ''}
              </div>
              ${m.link ? `<a href="${m.link}" target="_blank" rel="noopener noreferrer" class="text-xs text-amber-400 hover:text-amber-300">view ↗</a>` : ''}
            </div>
            ${m.body ? `<p class="text-sm text-gray-200 whitespace-pre-wrap break-words">${escapeHtml(m.body).slice(0, 800)}${m.body.length > 800 ? '...' : ''}</p>` : ''}
            ${m.media_descriptions && m.media_descriptions.length ? `
              <div class="mt-2 text-xs text-gray-500">📎 ${m.media_descriptions.map(escapeHtml).join(' · ')}</div>` : ''}
            ${m.brands && m.brands.length ? `
              <div class="mt-2 flex flex-wrap gap-1">
                ${m.brands.map(b => `<span class="text-xs bg-gray-800 px-2 py-0.5 rounded text-amber-300">${b}</span>`).join('')}
              </div>` : ''}
          </div>`).join('')}
      </div>
    </div>`;
}

function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function pivotToCrypto(address) {
  document.getElementById('crypto-address').value = address;
  document.querySelector('[data-tab="crypto"]').click();
  document.getElementById('crypto-btn').click();
}

function pivotToScanner(url) {
  document.getElementById('scan-url').value = url;
  document.querySelector('[data-tab="scanner"]').click();
  document.getElementById('scan-btn').click();
}

// ---- Sample button handler ----
// Pre-fills target input with sample value, then triggers the lookup button

document.querySelectorAll('.sample-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const sample = btn.dataset.sample;
    const targetId = btn.dataset.target;
    const triggerId = btn.dataset.trigger;
    const targetEl = document.getElementById(targetId);
    const triggerEl = document.getElementById(triggerId);
    if (targetEl) {
      targetEl.value = sample;
      targetEl.focus();
    }
    if (triggerEl) {
      // Slight delay so the input update visually registers before the click
      setTimeout(() => triggerEl.click(), 100);
    }
  });
});

// ---- Landing extras collapse on first investigation ----
// Hides the hero cards, threat pulse, examples grid, and news strip
// once the user runs their first crypto lookup.


// ---- IP Reputation ----

document.getElementById('ip-btn').addEventListener('click', runIpLookup);
document.getElementById('ip-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runIpLookup();
});

async function runIpLookup() {
  const raw = document.getElementById('ip-input').value.trim();
  const resultEl = document.getElementById('ip-result');

  if (!raw) return;

  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Querying Shodan InternetDB, GreyNoise, RIPEstat, URLhaus, and reverse DNS...</p>';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/ip/lookup/${encodeURIComponent(raw)}`);
    const data = await res.json();

    if (!res.ok) {
      resultEl.innerHTML = `<div class="bg-yellow-900/20 border border-yellow-700/30 rounded p-4">
        <p class="text-yellow-400 text-sm font-bold mb-1">Lookup failed</p>
        <p class="text-xs text-gray-400">${data.detail}</p>
      </div>`;
      return;
    }

    renderIpResult(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
}

function renderIpResult(el, data) {
  const cacheBadge = data.cache_hit
    ? '<span class="text-xs text-gray-500">cached</span>'
    : '<span class="text-xs text-green-400">fresh</span>';

  el.innerHTML = `
    ${renderIpSummary(data, cacheBadge)}
    ${renderIpClassification(data.greynoise)}
    ${renderIpPorts(data.shodan, data.cve_details)}
    ${renderIpUrlhaus(data.urlhaus)}
  `;
}

function renderIpSummary(data, cacheBadge) {
  const rs = data.ripestat || {};
  const ptr = data.reverse_dns || [];
  const ptrStr = ptr.length ? ptr.join(', ') : '<span class="text-gray-600">no PTR</span>';
  const locStr = [rs.city, rs.country].filter(Boolean).join(', ');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-3">
          <span class="brand-badge text-sm px-3 py-1">${data.ip}</span>
          ${locStr ? `<span class="text-xs text-gray-400">${locStr}</span>` : ''}
        </div>
        ${cacheBadge}
      </div>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-3">
        ${rs.asn ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">ASN</p><p class="text-amber-300 text-sm">AS${rs.asn}</p></div>` : ''}
        ${rs.asn_holder ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Network</p><p class="text-gray-200 text-sm">${rs.asn_holder}</p></div>` : ''}
        ${rs.prefix ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Prefix</p><p class="text-gray-200 text-sm font-mono">${rs.prefix}</p></div>` : ''}
      </div>
      <div>
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Reverse DNS</p>
        <p class="text-xs text-gray-300 font-mono break-all">${ptrStr}</p>
      </div>
    </div>`;
}

function renderIpClassification(gn) {
  if (!gn || (gn.message === undefined && !gn.classification)) return '';

  if (gn.message && gn.message.includes("not observed")) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-2 uppercase tracking-wide">GreyNoise Classification</h3>
        <p class="text-sm text-gray-400">Not observed scanning the internet or in the RIOT (known-benign) dataset.</p>
      </div>`;
  }

  const classification = gn.classification || 'unknown';
  const classColor = {
    'malicious': 'text-red-400 bg-red-900/30 border-red-700/50',
    'benign': 'text-green-400 bg-green-900/30 border-green-700/50',
    'unknown': 'text-gray-400 bg-gray-800 border-gray-700',
  }[classification] || 'text-gray-400 bg-gray-800';

  const tags = [];
  if (gn.noise) tags.push('Scanning the internet');
  if (gn.riot) tags.push('Known benign service (RIOT)');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">GreyNoise Classification</h3>
      <div class="flex items-center gap-3 mb-2">
        <span class="${classColor} border px-3 py-1 rounded text-xs font-bold uppercase">${classification}</span>
        ${gn.name && gn.name !== 'unknown' ? `<span class="text-sm text-gray-200">${gn.name}</span>` : ''}
      </div>
      ${tags.length ? `<p class="text-xs text-gray-400 mt-2">${tags.join(' · ')}</p>` : ''}
      ${gn.last_seen ? `<p class="text-xs text-gray-500 mt-1">Last seen: ${gn.last_seen}</p>` : ''}
      ${gn.link ? `<a href="${gn.link}" target="_blank" rel="noopener noreferrer" class="text-xs text-amber-400 hover:text-amber-300 mt-2 inline-block">View in GreyNoise ↗</a>` : ''}
    </div>`;
}

function renderIpPorts(shodan, cveDetails) {
  if (!shodan || shodan.empty) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-2 uppercase tracking-wide">Open Ports & Services (Shodan)</h3>
        <p class="text-sm text-gray-500">IP not in Shodan InternetDB or no open ports observed.</p>
      </div>`;
  }

  const ports = shodan.ports || [];
  const cpes = shodan.cpes || [];
  const hostnames = shodan.hostnames || [];
  const tags = shodan.tags || [];
  const vulns = shodan.vulns || [];

  const cveHtml = vulns.length ? `
    <div class="mt-3">
      <p class="text-xs text-red-400 font-bold uppercase tracking-wide mb-2">Known Vulnerabilities (${vulns.length})</p>
      <div class="space-y-2">
        ${vulns.slice(0, 10).map(cve => {
          const detail = (cveDetails && cveDetails[cve]) || {};
          const cvssBadge = detail.cvss ? `<span class="text-xs bg-red-900/40 text-red-300 px-2 py-0.5 rounded">CVSS ${detail.cvss}</span>` : '';
          const epssBadge = detail.epss ? `<span class="text-xs bg-orange-900/40 text-orange-300 px-2 py-0.5 rounded">EPSS ${(detail.epss * 100).toFixed(2)}%</span>` : '';
          const kevBadge = detail.kev ? `<span class="text-xs bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded">CISA KEV</span>` : '';
          return `
            <div class="bg-gray-950 rounded p-2 border border-gray-800">
              <div class="flex items-center gap-2 flex-wrap mb-1">
                <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener" class="text-amber-300 font-mono text-xs font-bold">${cve} ↗</a>
                ${cvssBadge} ${epssBadge} ${kevBadge}
              </div>
              ${detail.summary ? `<p class="text-xs text-gray-400">${detail.summary}</p>` : ''}
            </div>`;
        }).join('')}
        ${vulns.length > 10 ? `<p class="text-xs text-gray-500">... and ${vulns.length - 10} more</p>` : ''}
      </div>
    </div>` : '';

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Open Ports & Services (Shodan InternetDB)</h3>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-3">
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Ports</p>
          <div class="flex flex-wrap gap-1">
            ${ports.length ? ports.map(p => `<span class="text-xs bg-gray-800 text-amber-300 px-2 py-0.5 rounded font-mono">${p}</span>`).join('') : '<span class="text-xs text-gray-600">none</span>'}
          </div>
        </div>
        ${tags.length ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Tags</p><div class="flex flex-wrap gap-1">${tags.map(t => `<span class="text-xs bg-gray-800 text-gray-300 px-2 py-0.5 rounded">${t}</span>`).join('')}</div></div>` : ''}
      </div>
      ${hostnames.length ? `<div class="mb-2"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Hostnames</p><div class="flex flex-wrap gap-1">${hostnames.slice(0, 10).map(h => `<span class="text-xs bg-gray-800 text-gray-300 px-2 py-0.5 rounded font-mono">${h}</span>`).join('')}</div></div>` : ''}
      ${cpes.length ? `<div class="mb-2"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Software (CPEs)</p><div class="flex flex-wrap gap-1">${cpes.slice(0, 10).map(c => `<span class="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded font-mono">${c}</span>`).join('')}</div></div>` : ''}
      ${cveHtml}
    </div>`;
}

function renderIpUrlhaus(uh) {
  if (!uh || uh.query_status !== "ok") {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-2 uppercase tracking-wide">URLhaus History</h3>
        <p class="text-sm text-gray-500">No URLhaus records for this host.</p>
      </div>`;
  }

  const urls = uh.urls || [];
  const blacklists = uh.blacklists || {};
  const firstseen = uh.firstseen;
  const urlCount = uh.url_count || urls.length;

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">URLhaus History</h3>
        ${uh.urlhaus_reference ? `<a href="${uh.urlhaus_reference}" target="_blank" rel="noopener" class="text-xs text-amber-400 hover:text-amber-300">View on URLhaus ↗</a>` : ''}
      </div>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-3">
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Total Malicious URLs</p>
          <p class="text-red-400 font-bold">${urlCount}</p>
        </div>
        ${firstseen ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">First Seen</p><p class="text-amber-300 text-sm">${fmtPHT(firstseen)}</p></div>` : ''}
      </div>
      ${Object.keys(blacklists).length ? `<div class="mb-3"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Blacklist Status</p><div class="flex flex-wrap gap-2">${Object.entries(blacklists).map(([k, v]) => `<span class="text-xs bg-red-900/20 border border-red-700/30 px-2 py-1 rounded text-red-300">${k}: ${v}</span>`).join('')}</div></div>` : ''}
      ${urls.length ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Recent URLs (${Math.min(urls.length, 15)} of ${urls.length})</p><div class="space-y-1">${urls.slice(0, 15).map(u => `<div class="bg-gray-950 border border-gray-800 rounded p-2 flex items-center justify-between gap-2"><span class="text-xs text-amber-300 font-mono break-all flex-1">${u.url}</span><span class="text-xs ${u.url_status === 'online' ? 'text-green-400' : 'text-gray-500'} font-bold">${(u.url_status || 'unknown').toUpperCase()}</span></div>`).join('')}</div></div>` : ''}
    </div>`;
}

// ---- Sandbox History ----

document.getElementById('sandbox-btn').addEventListener('click', runSandboxLookup);
document.getElementById('sandbox-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runSandboxLookup();
});

async function runSandboxLookup() {
  const raw = document.getElementById('sandbox-input').value.trim();
  const resultEl = document.getElementById('sandbox-result');

  if (!raw) return;

  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Querying URLhaus and MalwareBazaar...</p>';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/sandbox/lookup?indicator=${encodeURIComponent(raw)}`);
    const data = await res.json();

    if (!res.ok) {
      resultEl.innerHTML = `<div class="bg-yellow-900/20 border border-yellow-700/30 rounded p-4">
        <p class="text-yellow-400 text-sm font-bold mb-1">Lookup failed</p>
        <p class="text-xs text-gray-400">${data.detail}</p>
      </div>`;
      return;
    }

    renderSandboxResult(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${e.message}</p>`;
  }
}

function renderSandboxResult(el, data) {
  const cacheBadge = data.cache_hit
    ? '<span class="text-xs text-gray-500">cached</span>'
    : '<span class="text-xs text-green-400">fresh</span>';

  el.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-3">
          <span class="brand-badge text-sm px-3 py-1">${data.indicator_type.toUpperCase()}</span>
          <span class="text-xs text-gray-400 break-all">${data.indicator}</span>
        </div>
        ${cacheBadge}
      </div>
    </div>
    ${renderUrlhausUrl(data.urlhaus_url)}
    ${renderUrlhausPayload(data.urlhaus_payload)}
    ${renderMalwarebazaar(data.malwarebazaar)}
  `;
}

function renderUrlhausUrl(uh) {
  if (!uh || uh.query_status !== "ok") {
    if (uh && uh.query_status === "no_results") {
      return `
        <div class="bg-gray-900 border border-gray-800 rounded p-5">
          <h3 class="text-sm font-bold text-gray-300 mb-2 uppercase tracking-wide">URLhaus URL Lookup</h3>
          <p class="text-sm text-gray-500">URL not present in URLhaus database.</p>
        </div>`;
    }
    return '';
  }

  const payloads = uh.payloads || [];
  const tags = uh.tags || [];
  const blacklists = uh.blacklists || {};

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">URLhaus URL Match</h3>
        ${uh.urlhaus_reference ? `<a href="${uh.urlhaus_reference}" target="_blank" rel="noopener" class="text-xs text-amber-400 hover:text-amber-300">View on URLhaus ↗</a>` : ''}
      </div>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-3">
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Status</p>
          <p class="text-${uh.url_status === 'online' ? 'green' : 'gray'}-400 font-bold uppercase text-sm">${uh.url_status || 'unknown'}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Threat</p>
          <p class="text-red-300 text-sm">${uh.threat || 'unknown'}</p>
        </div>
        ${uh.date_added ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">First Reported</p><p class="text-amber-300 text-sm">${fmtPHT(uh.date_added)}</p></div>` : ''}
      </div>
      ${tags.length ? `<div class="mb-3"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Tags</p><div class="flex flex-wrap gap-1">${tags.map(t => `<span class="text-xs bg-gray-800 text-amber-300 px-2 py-0.5 rounded">${t}</span>`).join('')}</div></div>` : ''}
      ${Object.keys(blacklists).length ? `<div class="mb-3"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Blacklists</p><div class="flex flex-wrap gap-2">${Object.entries(blacklists).map(([k, v]) => `<span class="text-xs bg-red-900/20 border border-red-700/30 px-2 py-1 rounded text-red-300">${k}: ${v}</span>`).join('')}</div></div>` : ''}
      ${payloads.length ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Associated Payloads (${payloads.length})</p><div class="space-y-2">${payloads.slice(0, 5).map(p => `<div class="bg-gray-950 border border-gray-800 rounded p-2"><p class="text-xs text-amber-300 font-mono break-all">${p.response_sha256 || p.response_md5 || ''}</p><p class="text-xs text-gray-400 mt-1">${p.file_type || '?'} · ${p.signature || 'no signature'}</p></div>`).join('')}</div></div>` : ''}
    </div>`;
}

function renderUrlhausPayload(uh) {
  if (!uh || uh.query_status !== "ok") return '';

  const urls = uh.urls || [];

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">URLhaus Hash Match</h3>
        ${uh.urlhaus_download ? `<a href="${uh.urlhaus_download}" target="_blank" rel="noopener" class="text-xs text-amber-400 hover:text-amber-300">Sample on URLhaus ↗</a>` : ''}
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
        <div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">File Type</p><p class="text-amber-300 text-sm">${uh.file_type || 'unknown'}</p></div>
        <div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">File Size</p><p class="text-gray-200 text-sm">${uh.file_size || '?'} bytes</p></div>
        <div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Signature</p><p class="text-red-300 text-sm">${uh.signature || 'none'}</p></div>
        ${uh.firstseen ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">First Seen</p><p class="text-gray-300 text-xs">${fmtPHT(uh.firstseen)}</p></div>` : ''}
      </div>
      ${urls.length ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Distribution URLs (${urls.length})</p><div class="space-y-1">${urls.slice(0, 10).map(u => `<div class="bg-gray-950 border border-gray-800 rounded p-2 flex items-center justify-between gap-2"><span class="text-xs text-amber-300 font-mono break-all flex-1">${u.url}</span><span class="text-xs ${u.url_status === 'online' ? 'text-green-400' : 'text-gray-500'} font-bold">${(u.url_status || 'unknown').toUpperCase()}</span></div>`).join('')}</div></div>` : ''}
    </div>`;
}

function renderMalwarebazaar(mb) {
  if (!mb || mb.query_status !== "ok") {
    if (mb && mb.query_status === "hash_not_found") {
      return `
        <div class="bg-gray-900 border border-gray-800 rounded p-5">
          <h3 class="text-sm font-bold text-gray-300 mb-2 uppercase tracking-wide">MalwareBazaar</h3>
          <p class="text-sm text-gray-500">Hash not present in MalwareBazaar.</p>
        </div>`;
    }
    return '';
  }

  const data = (mb.data && mb.data[0]) || {};
  const tags = data.tags || [];
  const yara = data.yara_rules || [];
  const intel = data.intelligence || {};

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">MalwareBazaar Match</h3>
        ${data.sha256_hash ? `<a href="https://bazaar.abuse.ch/sample/${data.sha256_hash}/" target="_blank" rel="noopener" class="text-xs text-amber-400 hover:text-amber-300">View on MalwareBazaar ↗</a>` : ''}
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
        <div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">File Name</p><p class="text-gray-200 text-sm break-all">${data.file_name || 'unknown'}</p></div>
        <div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">File Type</p><p class="text-amber-300 text-sm">${data.file_type || 'unknown'}</p></div>
        <div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Signature</p><p class="text-red-300 text-sm">${data.signature || 'none'}</p></div>
        ${data.first_seen ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">First Seen</p><p class="text-gray-300 text-xs">${fmtPHT(data.first_seen)}</p></div>` : ''}
      </div>
      ${tags.length ? `<div class="mb-3"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Tags</p><div class="flex flex-wrap gap-1">${tags.map(t => `<span class="text-xs bg-gray-800 text-amber-300 px-2 py-0.5 rounded">${t}</span>`).join('')}</div></div>` : ''}
      ${yara.length ? `<div class="mb-3"><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">YARA Rule Hits</p><div class="flex flex-wrap gap-1">${yara.slice(0, 10).map(y => `<span class="text-xs bg-red-900/20 border border-red-700/30 px-2 py-1 rounded text-red-300 font-mono">${y.rule_name || y}</span>`).join('')}</div></div>` : ''}
      ${intel.downloads ? `<p class="text-xs text-gray-500">Downloaded ${intel.downloads} times · ${intel.uploads || 0} unique uploaders</p>` : ''}
    </div>`;
}

// ---- PH Threat Pulse widget ----

async function loadThreatPulse() {
  const contentEl = document.getElementById('threat-pulse-content');
  const statusEl = document.getElementById('threat-pulse-status');
  if (!contentEl) return;

  try {
    const res = await fetch('/api/threat-pulse');
    if (!res.ok) {
      console.error('loadThreatPulse: HTTP', res.status);
      contentEl.innerHTML = `<p class="text-xs text-red-400">Failed to load threat pulse (HTTP ${res.status}).</p>`;
      return;
    }
    const data = await res.json();

    if (data.error) {
      contentEl.innerHTML = `<p class="text-xs text-yellow-500">${data.error}</p>`;
      statusEl.textContent = '';
      return;
    }

    const fetchedAt = data.fetched_at ? fmtPHT(data.fetched_at) : 'just now';
    const staleNote = data.stale ? ' · stale cache (URLhaus unreachable)' : '';
    statusEl.textContent = `updated ${fetchedAt}${staleNote}`;

    const brandsHtml = data.top_brands && data.top_brands.length > 0
      ? data.top_brands.slice(0, 6).map(([brand, count]) => `
          <span class="inline-flex items-center gap-1 bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs">
            <span class="text-gray-400">${brand}:</span>
            <span class="text-amber-300 font-bold">${count}</span>
          </span>`).join('')
      : '<span class="text-xs text-gray-600">no brand patterns matched in feed</span>';

    const latestHtml = data.latest && data.latest.length > 0
      ? data.latest.slice(0, 3).map(item => `
          <div class="bg-gray-950 border border-gray-800 rounded p-2 flex items-center justify-between gap-3">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs bg-gray-800 text-amber-300 px-1.5 py-0.5 rounded">${escapeHtml(item.brand)}</span>
                <span class="text-xs ${item.url_status === 'online' ? 'text-green-400' : 'text-gray-500'} font-bold">${escapeHtml((item.url_status || 'unknown').toUpperCase())}</span>
                <span class="text-xs text-gray-600">${item.dateadded ? escapeHtml(item.dateadded.split(' ')[0]) : ''}</span>
              </div>
              <p class="text-xs text-gray-300 font-mono truncate">${escapeHtml(item.url)}</p>
            </div>
            <button class="text-xs bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 font-bold px-3 py-1 rounded transition whitespace-nowrap"
                    onclick="pivotThreatPulseToScanner('${item.url.replace(/'/g, "\\'")}')">
              Scan
            </button>
          </div>`).join('')
      : '<p class="text-xs text-gray-600">No recent PH-targeting URLs in feed.</p>';

    contentEl.innerHTML = `
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Last 24h</p>
          <p class="text-amber-300 font-bold text-2xl">${data.count_24h}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Last 7d</p>
          <p class="text-amber-300 font-bold text-2xl">${data.count_7d}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Currently Live</p>
          <p class="text-red-400 font-bold text-2xl">${data.live_count}</p>
        </div>
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Total Tracked</p>
          <p class="text-gray-200 font-bold text-2xl">${data.total_tracked}</p>
        </div>
      </div>

      <div class="mb-4">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Top Impersonated Brands</p>
        <div class="flex flex-wrap gap-2">${brandsHtml}</div>
      </div>

      <div>
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Latest URLs</p>
        <div class="space-y-2">${latestHtml}</div>
      </div>
    `;
  } catch (e) {
    contentEl.innerHTML = `<p class="text-xs text-red-400">Failed to load threat pulse: ${e.message}</p>`;
  }
}

function pivotThreatPulseToScanner(url) {
  document.getElementById('scan-url').value = url;
  document.querySelector('[data-tab="scanner"]').click();
  document.getElementById('scan-btn').click();
}

// ---- Example cards (delegated handler, works regardless of DOM ready timing) ----

document.body.addEventListener('click', (e) => {
  const card = e.target.closest('.example-card');
  if (!card) return;

  const tab = card.dataset.tab;
  const targetId = card.dataset.target;
  const triggerId = card.dataset.trigger;
  const value = card.dataset.value;

  if (!tab || !targetId || !triggerId || !value) {
    console.warn('example-card missing required data attributes:', card);
    return;
  }

  const tabBtn = document.querySelector(`[data-tab="${tab}"]`);
  if (tabBtn) {
    tabBtn.click();
  } else {
    console.warn('example-card: tab button not found for tab', tab);
    return;
  }

  setTimeout(() => {
    const targetEl = document.getElementById(targetId);
    const triggerEl = document.getElementById(triggerId);
    if (!targetEl) {
      console.warn('example-card: target input not found:', targetId);
      return;
    }
    if (!triggerEl) {
      console.warn('example-card: trigger button not found:', triggerId);
      return;
    }
    targetEl.value = value;
    triggerEl.click();
  }, 200);
});

// ---- Landing news strip ----

async function loadLandingNews() {
  const el = document.getElementById('landing-news');
  if (!el) return;

  try {
    const res = await fetch('/api/news/global_cyber');
    if (!res.ok) {
      console.error('loadLandingNews: HTTP', res.status);
      el.innerHTML = `<p class="text-xs text-red-400 col-span-3">Failed to load news (HTTP ${res.status}).</p>`;
      return;
    }
    const data = await res.json();

    if (!data || data.length === 0) {
      el.innerHTML = '<p class="text-xs text-gray-500 col-span-3">No headlines available.</p>';
      return;
    }

    el.innerHTML = data.slice(0, 3).map(item => {
      const safeUrl = /^https?:\/\//i.test(item.url) ? item.url : '#';
      return `
      <a href="${escapeAttr(safeUrl)}" target="_blank" rel="noopener noreferrer"
         class="bg-gray-900 border border-gray-800 hover:border-amber-400 rounded p-3 block transition">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-amber-400 font-bold">${escapeHtml(item.feed_source)}</span>
          <span class="text-xs text-gray-600">${fmtPHT(item.published_at)}</span>
        </div>
        <p class="text-sm text-white leading-snug line-clamp-3">${escapeHtml(item.title)}</p>
      </a>`;
    }).join('');
  } catch (e) {
    el.innerHTML = `<p class="text-xs text-red-400 col-span-3">Failed to load news: ${e.message}</p>`;
  }
}

// ---- Email Header Analyzer ----

document.getElementById('email-header-clear')?.addEventListener('click', () => {
  document.getElementById('email-header-input').value = '';
  const bodyEl = document.getElementById('email-body-input');
  if (bodyEl) bodyEl.value = '';
  const resultEl = document.getElementById('email-header-result');
  resultEl.classList.add('hidden');
  resultEl.innerHTML = '';
});

document.getElementById('email-header-btn')?.addEventListener('click', async () => {
  const input = document.getElementById('email-header-input');
  const resultEl = document.getElementById('email-header-result');
  const btn = document.getElementById('email-header-btn');
  const raw = (input.value || '').trim();

  if (!raw) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Paste an email header first.</p>';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Analyzing...';
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Parsing header and running DNS lookups...</p>';

  try {
    const rawBody = (document.getElementById('email-body-input')?.value || '').trim();
    const res = await fetch('/api/email-header/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({raw_header: raw, raw_body: rawBody || null}),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: `HTTP ${res.status}`}));
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Analysis failed: ${err.detail || res.status}</p>`;
      return;
    }

    const data = await res.json();
    resultEl.innerHTML = renderEmailHeaderResult(data);
  } catch (e) {
    console.error('email-header analyze exception:', e);
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Network error: ${e.message}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Header';
  }
});


function renderEmailHeaderResult(d) {
  const bec = d.bec_assessment || {};
  const auth = d.authentication || {};
  const from = (d.from || [])[0] || {};
  const replyTo = (d.reply_to || [])[0] || {};
  const returnPath = (d.return_path || [])[0] || {};

  const verdictColor = {
    'high_risk': 'red',
    'medium_risk': 'amber',
    'low_risk_with_indicators': 'yellow',
    'low_risk': 'green',
  }[bec.verdict] || 'gray';

  const verdictLabel = {
    'high_risk': 'HIGH RISK',
    'medium_risk': 'MEDIUM RISK',
    'low_risk_with_indicators': 'LOW RISK (with indicators)',
    'low_risk': 'LOW RISK',
  }[bec.verdict] || 'UNKNOWN';

  let summaryHtml = '';
  if (bec.llm_scam_type || bec.llm_summary) {
    const scamType = bec.llm_scam_type || 'Email analyzed';
    const summaryText = bec.llm_summary || '';
    summaryHtml = `
      <div class="bg-gradient-to-br from-gray-900 to-gray-950 border-l-4 border-${verdictColor}-500 rounded p-5 mb-4">
        <div class="flex items-start gap-3">
          <div class="flex-shrink-0 mt-1">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-${verdictColor}-400">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" x2="12" y1="8" y2="12"/>
              <line x1="12" x2="12.01" y1="16" y2="16"/>
            </svg>
          </div>
          <div class="flex-1">
            <div class="flex items-center justify-between mb-2">
              <h3 class="text-xs uppercase tracking-widest text-gray-500">Summary</h3>
              <span class="text-xs text-gray-600 font-mono">Claude Haiku 4.5</span>
            </div>
            <p class="text-lg font-bold text-${verdictColor}-300 mb-2">${escapeHtml(scamType)}</p>
            <p class="text-sm text-gray-300 leading-relaxed">${escapeHtml(summaryText)}</p>
          </div>
        </div>
      </div>
    `;
  }

  let html = summaryHtml;

  html += `
    <div class="bg-gray-900 border border-${verdictColor}-500 rounded p-5 mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-${verdictColor}-400 uppercase tracking-wider">Email Risk Assessment</h3>
        <span class="text-2xl font-bold text-${verdictColor}-400">${verdictLabel}</span>
      </div>
      <div class="mb-3">
        <div class="text-xs text-gray-500 uppercase mb-1">Risk Score</div>
        <div class="bg-gray-800 rounded h-3 overflow-hidden">
          <div class="bg-${verdictColor}-500 h-3" style="width:${bec.score || 0}%"></div>
        </div>
        <div class="text-xs text-gray-400 mt-1">${bec.score || 0} / 100</div>
      </div>
      <div class="space-y-2">
        ${(bec.indicators || []).map(ind => `
          <div class="flex items-start gap-2 text-xs">
            <span class="font-bold uppercase ${
              ind.severity === 'high' ? 'text-red-400' :
              ind.severity === 'medium' ? 'text-amber-400' :
              ind.severity === 'info' ? 'text-blue-400' : 'text-gray-400'
            }">${ind.severity}</span>
            <span class="text-white">${escapeHtml(ind.name)}:</span>
            <span class="text-gray-400">${escapeHtml(ind.detail)}</span>
          </div>
        `).join('') || '<p class="text-xs text-gray-500">No suspicious indicators found.</p>'}
      </div>
    </div>
  `;

  if (d.llm_analysis && d.llm_analysis._usage) {
    const u = d.llm_analysis._usage;
    html += `
      <p class="text-xs text-gray-700 mb-6 text-right font-mono">
        ${escapeHtml(u.model || 'LLM')}: ${u.input_tokens || 0} in + ${u.output_tokens || 0} out tokens
        ${u.cache_read_input_tokens ? `(${u.cache_read_input_tokens} cached)` : ''}
      </p>
    `;
  }

  if (d.llm_analysis && d.llm_analysis.rate_limited) {
    html += `
      <div class="bg-amber-950 border border-amber-700 rounded p-3 mb-6">
        <p class="text-xs text-amber-300">${escapeHtml(d.llm_analysis.message)}</p>
      </div>
    `;
  }

  if (d.body_provided && d.body_analysis) {
    const ba = d.body_analysis;
    const catLabels = {
      urgency: 'Urgency / pressure',
      threat: 'Threat language',
      authority_impersonation: 'Authority impersonation',
      financial_lure: 'Financial lure',
      credential_phishing: 'Credential phishing',
      crypto_scam: 'Crypto scam',
      romance: 'Romance / pig butchering',
      invoice_wire_fraud: 'Invoice / wire fraud',
      url_deception: 'URL deception',
      crypto_address_in_body: 'Crypto address in body',
      suspicious_attachment: 'Suspicious attachment',
      reply_trap: 'Reply trap',
      homoglyph: 'Homoglyph attack',
    };
    const catKeys = Object.keys(ba.category_hits || {});
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Body Analysis</h3>
        ${catKeys.length === 0 ? '<p class="text-xs text-green-400">No scam patterns detected in body.</p>' : `
          <div class="flex flex-wrap gap-2 mb-3">
            ${catKeys.map(k => `<span class="bg-red-900 text-red-300 text-xs font-bold px-2 py-0.5 rounded">${escapeHtml(catLabels[k] || k)}</span>`).join('')}
          </div>
        `}
        ${ba.crypto_addresses && ba.crypto_addresses.length > 0 ? `
          <div class="mb-3">
            <p class="text-xs text-gray-500 uppercase mb-2">Crypto Addresses in Body (${ba.crypto_addresses.length})</p>
            <div class="flex flex-wrap gap-2">
              ${ba.crypto_addresses.map(ca => `
                <button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition"
                        onclick="pivotToCrypto('${escapeAttr(ca.address)}')">${escapeHtml(ca.type)}: ${escapeHtml(ca.address.slice(0, 16) + '...')}</button>
              `).join('')}
            </div>
          </div>
        ` : ''}
        ${ba.urls && ba.urls.length > 0 ? `
          <div class="mb-3">
            <p class="text-xs text-gray-500 uppercase mb-2">URLs in Body (${ba.urls.length})</p>
            <div class="flex flex-wrap gap-2">
              ${ba.urls.slice(0, 10).map(u => `
                <button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition"
                        onclick="pivotToScanner('${escapeAttr(u)}')">${escapeHtml(u.length > 60 ? u.slice(0, 60) + '...' : u)}</button>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }

  html += `
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
      ${emailAuthCard('SPF', auth.spf, d.spf_live)}
      ${emailAuthCard('DKIM', auth.dkim, d.dkim_live)}
      ${emailAuthCard('DMARC', auth.dmarc, d.dmarc_live)}
    </div>
  `;

  html += `
    <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
      <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Sender Identity</h3>
      <table class="w-full text-xs">
        <tr class="border-b border-gray-800">
          <td class="py-2 text-gray-500 uppercase">From</td>
          <td class="py-2 text-white font-mono">
            ${from.display ? `<span class="text-amber-300">${escapeHtml(from.display)}</span> ` : ''}
            &lt;${escapeHtml(from.email || '(none)')}&gt;
          </td>
        </tr>
        <tr class="border-b border-gray-800">
          <td class="py-2 text-gray-500 uppercase">Reply-To</td>
          <td class="py-2 text-white font-mono">${escapeHtml(replyTo.email || '(same as From)')}</td>
        </tr>
        <tr class="border-b border-gray-800">
          <td class="py-2 text-gray-500 uppercase">Return-Path</td>
          <td class="py-2 text-white font-mono">${escapeHtml(returnPath.email || '(none)')}</td>
        </tr>
        <tr class="border-b border-gray-800">
          <td class="py-2 text-gray-500 uppercase">Subject</td>
          <td class="py-2 text-white">${escapeHtml(d.subject || '(none)')}</td>
        </tr>
        <tr class="border-b border-gray-800">
          <td class="py-2 text-gray-500 uppercase">Date</td>
          <td class="py-2 text-white">${escapeHtml(d.date || '(none)')}</td>
        </tr>
        <tr>
          <td class="py-2 text-gray-500 uppercase">Message-ID</td>
          <td class="py-2 text-white font-mono text-xs break-all">${escapeHtml(d.message_id || '(none)')}</td>
        </tr>
      </table>
    </div>
  `;

  if (d.originating_ip) {
    const oip = d.originating_ip;
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider">Originating IP</h3>
          <button class="text-xs bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 font-bold px-3 py-1 rounded transition"
                  onclick="pivotToIp('${escapeAttr(oip.ip)}')">
            Investigate in IP Reputation
          </button>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div><div class="text-gray-500 uppercase">IP</div><div class="text-white font-mono">${escapeHtml(oip.ip)}</div></div>
          <div><div class="text-gray-500 uppercase">Reverse DNS</div><div class="text-white font-mono break-all">${escapeHtml(oip.rdns || '-')}</div></div>
          <div><div class="text-gray-500 uppercase">ASN</div><div class="text-white">${escapeHtml(String(oip.asn || '-'))}</div></div>
          <div><div class="text-gray-500 uppercase">Country</div><div class="text-white">${escapeHtml(oip.country || '-')}</div></div>
        </div>
      </div>
    `;
  }

  if (d.received_chain && d.received_chain.length > 0) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Received Chain (oldest first)</h3>
        <div class="space-y-2">
          ${d.received_chain.map((hop, i) => `
            <div class="bg-gray-950 border border-gray-800 rounded p-3 text-xs">
              <div class="flex items-center gap-2 mb-1">
                <span class="bg-amber-400 text-gray-950 font-bold px-2 py-0.5 rounded text-xs">${i}</span>
                ${hop.delay_seconds !== undefined ? `<span class="text-gray-600">+${Math.round(hop.delay_seconds)}s</span>` : ''}
                ${hop.timestamp ? `<span class="text-gray-500">${fmtPHT(hop.timestamp)}</span>` : ''}
              </div>
              <div class="text-gray-400 font-mono break-all">
                ${hop.from_host ? `from <span class="text-white">${escapeHtml(hop.from_host)}</span>` : ''}
                ${hop.ip ? `[<span class="text-amber-300 cursor-pointer hover:underline" onclick="pivotToIp('${escapeAttr(hop.ip)}')">${escapeHtml(hop.ip)}</span>]` : ''}
                ${hop.by_host ? `by <span class="text-white">${escapeHtml(hop.by_host)}</span>` : ''}
                ${hop.with_protocol ? `with <span class="text-gray-500">${escapeHtml(hop.with_protocol)}</span>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const iocs = d.iocs || {};
  const iocTotal = (iocs.urls?.length || 0) + (iocs.ips?.length || 0) + (iocs.sha256?.length || 0);
  if (iocTotal > 0) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Extracted IOCs</h3>
        ${iocs.urls?.length ? `
          <div class="mb-3">
            <p class="text-xs text-gray-500 uppercase mb-2">URLs (${iocs.urls.length})</p>
            <div class="flex flex-wrap gap-2">
              ${iocs.urls.map(u => `
                <button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition"
                        onclick="pivotToScanner('${escapeAttr(u)}')">${escapeHtml(u.length > 70 ? u.slice(0, 70) + '...' : u)}</button>
              `).join('')}
            </div>
          </div>
        ` : ''}
        ${iocs.ips?.length ? `
          <div class="mb-3">
            <p class="text-xs text-gray-500 uppercase mb-2">IPs (${iocs.ips.length})</p>
            <div class="flex flex-wrap gap-2">
              ${iocs.ips.map(ip => `
                <button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition"
                        onclick="pivotToIp('${escapeAttr(ip)}')">${escapeHtml(ip)}</button>
              `).join('')}
            </div>
          </div>
        ` : ''}
        ${iocs.sha256?.length ? `
          <div class="mb-3">
            <p class="text-xs text-gray-500 uppercase mb-2">SHA256 hashes (${iocs.sha256.length})</p>
            <div class="flex flex-wrap gap-2">
              ${iocs.sha256.map(h => `
                <button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition"
                        onclick="pivotToSandbox('${escapeAttr(h)}')">${escapeHtml(h.slice(0, 16) + '...')}</button>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }

  if (d.x_headers && Object.keys(d.x_headers).length > 0) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
        <details>
          <summary class="text-sm font-bold text-gray-300 uppercase tracking-wider cursor-pointer">X-Headers (${Object.keys(d.x_headers).length})</summary>
          <table class="w-full text-xs mt-3">
            ${Object.entries(d.x_headers).map(([k, v]) => `
              <tr class="border-b border-gray-800">
                <td class="py-1 pr-3 text-gray-500 font-mono align-top">${escapeHtml(k)}</td>
                <td class="py-1 text-white font-mono break-all">${escapeHtml((v || '').slice(0, 300))}</td>
              </tr>
            `).join('')}
          </table>
        </details>
      </div>
    `;
  }

  if (d.user_agent || d.list_unsubscribe || d.auto_submitted) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Mail Client / Metadata</h3>
        <div class="space-y-2 text-xs">
          ${d.user_agent ? `<div><span class="text-gray-500 uppercase mr-2">Mailer:</span><span class="text-white font-mono">${escapeHtml(d.user_agent)}</span></div>` : ''}
          ${d.list_unsubscribe ? `<div><span class="text-gray-500 uppercase mr-2">List-Unsubscribe:</span><span class="text-white font-mono break-all">${escapeHtml(d.list_unsubscribe)}</span></div>` : ''}
          ${d.auto_submitted ? `<div><span class="text-gray-500 uppercase mr-2">Auto-Submitted:</span><span class="text-white font-mono">${escapeHtml(d.auto_submitted)}</span></div>` : ''}
        </div>
      </div>
    `;
  }

  return html;
}


function emailAuthCard(name, result, live) {
  const color = {
    pass: 'green',
    fail: 'red',
    softfail: 'amber',
    neutral: 'gray',
    none: 'gray',
    temperror: 'amber',
    permerror: 'red',
  }[result] || 'gray';

  const label = (result || 'none').toUpperCase();

  let liveBlock = '';
  if (live) {
    if (live.found) {
      liveBlock = `<p class="text-xs text-gray-400 mt-2 font-mono break-all">${escapeHtml((live.record || '').slice(0, 200))}</p>`;
      if (live.policy) {
        liveBlock += `<p class="text-xs text-gray-500 mt-1">Policy: <span class="text-amber-300">${escapeHtml(live.policy)}</span></p>`;
      }
    } else {
      liveBlock = `<p class="text-xs text-gray-600 mt-2">No record published</p>`;
    }
  }

  return `
    <div class="bg-gray-900 border border-${color}-500 rounded p-4">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs text-gray-500 uppercase tracking-wider">${name}</span>
        <span class="text-${color}-400 font-bold text-sm">${label}</span>
      </div>
      ${liveBlock}
    </div>
  `;
}


function pivotToIp(ip) {
  window.location.hash = '#ip';
  setTimeout(() => {
    const input = document.getElementById('ip-input');
    const btn = document.getElementById('ip-btn');
    if (input && btn) {
      input.value = ip;
      btn.click();
    }
  }, 200);
}


function pivotToSandbox(value) {
  window.location.hash = '#sandbox';
  setTimeout(() => {
    const input = document.getElementById('sandbox-input');
    const btn = document.getElementById('sandbox-btn');
    if (input && btn) {
      input.value = value;
      btn.click();
    }
  }, 200);
}


function escapeAttr(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}


// ---- Google Dork Generator ----

document.querySelectorAll('.dork-preset').forEach(btn => {
  btn.addEventListener('click', () => {
    const goal = btn.dataset.goal || '';
    const goalEl = document.getElementById('dork-goal');
    if (goalEl) {
      goalEl.value = goal;
      goalEl.focus();
    }
  });
});

document.getElementById('dork-clear-btn')?.addEventListener('click', () => {
  document.getElementById('dork-goal').value = '';
  document.getElementById('dork-target').value = '';
  const result = document.getElementById('dork-result');
  result.classList.add('hidden');
  result.innerHTML = '';
});

document.getElementById('dork-generate-btn')?.addEventListener('click', async () => {
  const goalEl = document.getElementById('dork-goal');
  const targetEl = document.getElementById('dork-target');
  const resultEl = document.getElementById('dork-result');
  const btn = document.getElementById('dork-generate-btn');

  const goal = (goalEl.value || '').trim();
  const target = (targetEl.value || '').trim();

  if (!goal) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Describe what you want to find first.</p>';
    return;
  }
  if (goal.length < 10) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Goal too short. Add more detail about what you want to find.</p>';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Generating...';
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Calling Claude Haiku 4.5 to generate dorks...</p>';

  try {
    const res = await fetch('/api/dork-generator/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({goal: goal, target: target || null}),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: `HTTP ${res.status}`}));
      resultEl.innerHTML = `<p class="text-red-400 text-sm">${escapeHtml(err.detail || `Request failed (${res.status})`)}</p>`;
      return;
    }

    const data = await res.json();
    resultEl.innerHTML = renderDorkResult(data);
  } catch (e) {
    console.error('dork generator exception:', e);
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Network error: ${escapeHtml(e.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Dorks';
  }
});


function renderDorkResult(d) {
  if (d.refused) {
    return `
      <div class="bg-amber-950 border border-amber-700 rounded p-5 mb-6">
        <h3 class="text-sm font-bold text-amber-400 uppercase tracking-wider mb-2">Request Declined</h3>
        <p class="text-sm text-amber-200">${escapeHtml(d.refusal_reason || 'The generator declined this request.')}</p>
        <p class="text-xs text-amber-300 mt-2">Try rephrasing your goal in terms of an organization, domain, or general category rather than a specific named individual.</p>
      </div>
    `;
  }

  const dorks = d.dorks || [];
  if (dorks.length === 0) {
    return '<p class="text-gray-400 text-sm">No dorks generated. Try rephrasing your goal.</p>';
  }

  let html = `
    <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider">Generated Dorks (${dorks.length})</h3>
        ${d.target ? `<span class="text-xs text-gray-500">Target: <span class="text-amber-300 font-mono">${escapeHtml(d.target)}</span></span>` : ''}
      </div>
      ${d.notes ? `<p class="text-xs text-gray-400 mb-4 italic border-l-2 border-gray-700 pl-3">${escapeHtml(d.notes)}</p>` : ''}
      <div class="space-y-4">
  `;

  dorks.forEach((dk, idx) => {
    const riskColor = {
      'high_impact': 'red',
      'sensitive': 'amber',
      'info': 'blue',
    }[dk.risk_level] || 'gray';
    const riskLabel = {
      'high_impact': 'HIGH IMPACT',
      'sensitive': 'SENSITIVE',
      'info': 'INFO',
    }[dk.risk_level] || (dk.risk_level || 'INFO').toUpperCase();

    const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(dk.query)}`;

    html += `
      <div class="bg-gray-950 border border-${riskColor}-700 rounded p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-gray-500">#${idx + 1}</span>
          <span class="text-xs font-bold px-2 py-0.5 rounded bg-${riskColor}-900 text-${riskColor}-300">${riskLabel}</span>
        </div>
        <div class="bg-black border border-gray-800 rounded p-3 mb-3 font-mono text-xs text-amber-300 break-all relative group">
          <button class="absolute top-1 right-1 text-xs bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 px-2 py-0.5 rounded opacity-0 group-hover:opacity-100 transition"
                  onclick="copyDorkToClipboard(this, '${escapeAttr(dk.query)}')">Copy</button>
          ${escapeHtml(dk.query)}
        </div>
        <div class="space-y-2 text-xs">
          <div>
            <span class="text-gray-500 uppercase tracking-wider">What it finds:</span>
            <span class="text-gray-300 ml-2">${escapeHtml(dk.explanation || '')}</span>
          </div>
          <div>
            <span class="text-green-500 uppercase tracking-wider">Defensive use:</span>
            <span class="text-gray-300 ml-2">${escapeHtml(dk.defensive_use || '')}</span>
          </div>
        </div>
        <div class="mt-3 flex gap-2">
          <a href="${googleUrl}" target="_blank" rel="noopener noreferrer"
             class="text-xs bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 font-bold px-3 py-1.5 rounded transition inline-flex items-center gap-1">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>
            Search on Google
          </a>
        </div>
      </div>
    `;
  });

  html += '</div></div>';

  if (d._usage) {
    const u = d._usage;
    html += `
      <p class="text-xs text-gray-700 mb-6 text-right font-mono">
        ${escapeHtml(u.model || 'LLM')}: ${u.input_tokens || 0} in + ${u.output_tokens || 0} out tokens
        ${u.cache_read_input_tokens ? `(${u.cache_read_input_tokens} cached)` : ''}
        ${d.cache_hit ? '· result from cache' : ''}
      </p>
    `;
  }

  return html;
}


function copyDorkToClipboard(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('bg-green-500', 'text-gray-950');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('bg-green-500', 'text-gray-950');
    }, 1500);
  }).catch(() => {
    btn.textContent = 'Copy failed';
  });
}


// ---- Email client header retrieval guide ----

const EMAIL_CLIENT_INSTRUCTIONS = {
  'gmail': {
    title: 'Gmail (web)',
    steps: [
      'Open the message in your inbox.',
      'Click the three-dot menu in the top right of the message (next to the Reply button).',
      'Select "Show original".',
      'A new tab opens with the raw message. Click "Copy to clipboard" at the top, OR scroll to the "Original Message" section and select everything from the first "Received:" or "Delivered-To:" line down to the empty line before the body.',
      'Paste into the textarea above, or click "Download Original" to save as .eml and upload it instead.',
    ],
    note: 'The "Show original" page also includes a summary box at the top with SPF / DKIM / DMARC results, but the analyzer here goes deeper.',
  },
  'owa': {
    title: 'Outlook on the Web (OWA / outlook.office.com / outlook.live.com)',
    steps: [
      'Open the message.',
      'Click the three-dot menu at the top right of the message.',
      'Hover over "View" and select "View message source" (or in some versions: "Message details").',
      'A modal or new window opens with the raw message.',
      'Select all text and copy, then paste into the textarea above.',
    ],
  },
  'outlook-desktop': {
    title: 'Outlook for Windows (Classic and New)',
    steps: [
      'Classic Outlook: Open the message in its own window (double-click it). Go to File menu → Properties. The "Internet headers" box at the bottom contains the header.',
      'For full message export: File menu → Save As → choose .msg format. Then upload the .msg file above.',
      'New Outlook: Open the message. Click the three-dot menu → View → View message source.',
    ],
    note: 'Outlook .msg files are the preferred upload format for Windows users. The analyzer parses them natively.',
  },
  'outlook-mac': {
    title: 'Outlook for Mac',
    steps: [
      'Open the message.',
      'Go to View menu → Message → Internet Headers (or right-click the message and select "View Source").',
      'Copy the displayed header text and paste into the textarea above.',
      'Alternative: File menu → Save As → choose .eml format, then upload the file.',
    ],
  },
  'apple-mail': {
    title: 'Apple Mail (macOS)',
    steps: [
      'Open the message.',
      'Go to View menu → Message → Raw Source (keyboard shortcut: Cmd + Option + U).',
      'A new window opens with the full raw message.',
      'Select the header section and copy, then paste into the textarea above.',
      'Alternative: drag the message from the inbox to the Desktop. macOS creates a .eml file you can upload.',
    ],
    note: 'If "Raw Source" is greyed out, the message may still be downloading. Wait a few seconds and try again.',
  },
  'thunderbird': {
    title: 'Mozilla Thunderbird',
    steps: [
      'Open the message.',
      'Go to View menu → Message Source (keyboard shortcut: Ctrl+U on Windows/Linux, Cmd+U on Mac).',
      'A new window opens with the full raw message.',
      'Copy the header section and paste into the textarea above.',
      'Alternative: File menu → Save As → .eml format, then upload.',
    ],
  },
  'emclient': {
    title: 'eM Client',
    steps: [
      'Right-click the message in the message list.',
      'Select View → Show source.',
      'A new window opens with the raw message.',
      'Copy the header section and paste into the textarea above.',
    ],
    note: 'eM Client also has a "Headers" tab at the bottom of the message preview that shows just the header without the body.',
  },
  'proton': {
    title: 'ProtonMail',
    steps: [
      'Open the message.',
      'Click the three-dot menu at the top right of the message.',
      'Select "View headers".',
      'A panel opens showing the raw headers.',
      'Copy the entire header text and paste into the textarea above.',
    ],
    note: 'ProtonMail strips some headers for privacy (e.g. the sender IP is replaced with a Proton internal hop). Auth results from the originating server are preserved.',
  },
  'yahoo': {
    title: 'Yahoo Mail',
    steps: [
      'Open the message.',
      'Click the three-dot menu at the top of the message.',
      'Select "View raw message".',
      'A new window opens with the full raw message.',
      'Copy the header section and paste into the textarea above.',
    ],
  },
  'mobile': {
    title: 'Mobile (iOS Mail, Gmail app, Outlook app, etc.)',
    steps: [
      'Mobile apps generally do NOT expose raw email headers.',
      'Workaround 1: forward the suspicious message to yourself, then open the forwarded copy on a desktop client.',
      "Workaround 2: open your mail provider in the phone's browser (Gmail web, Outlook web) which exposes \"Show original\" / \"View source\" the same way as desktop.",
    ],
    note: 'Forwarded messages introduce new Received hops and the original SPF/DKIM/DMARC results may no longer be valid. Prefer the web interface approach when possible.',
  },
};


function renderEmailClientInstructions(client) {
  const c = EMAIL_CLIENT_INSTRUCTIONS[client];
  const target = document.getElementById('email-client-instructions');
  if (!c || !target) return;

  const stepsHtml = c.steps.map((step, i) => `
    <li class="flex gap-3 mb-2">
      <span class="text-amber-400 font-bold text-xs flex-shrink-0 mt-0.5">${i + 1}.</span>
      <span class="text-sm text-gray-300">${escapeHtml(step)}</span>
    </li>
  `).join('');

  target.innerHTML = `
    <h4 class="text-sm font-bold text-white mb-3">${escapeHtml(c.title)}</h4>
    <ol class="mb-3">${stepsHtml}</ol>
    ${c.note ? `<p class="text-xs text-gray-500 italic mt-3 border-t border-gray-800 pt-3">${escapeHtml(c.note)}</p>` : ''}
  `;
}


document.querySelectorAll('.email-client-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const client = btn.dataset.client;
    document.querySelectorAll('.email-client-btn').forEach(b => {
      b.classList.remove('bg-amber-400', 'text-gray-950');
      b.classList.add('bg-gray-800', 'hover:bg-gray-700', 'text-gray-300');
    });
    btn.classList.remove('bg-gray-800', 'hover:bg-gray-700', 'text-gray-300');
    btn.classList.add('bg-amber-400', 'text-gray-950');
    renderEmailClientInstructions(client);
  });
});

if (document.getElementById('email-client-instructions')) {
  renderEmailClientInstructions('gmail');
}

const emailAnalyzeBtnEl = document.getElementById('email-header-btn');
const emailHelpEl = document.getElementById('email-header-help');
if (emailAnalyzeBtnEl && emailHelpEl) {
  emailAnalyzeBtnEl.addEventListener('click', () => {
    setTimeout(() => { emailHelpEl.open = false; }, 1500);
  });
}


// ---- Email file upload ----

const emailDropzone = document.getElementById('email-upload-dropzone');
const emailFileInput = document.getElementById('email-file-input');
const emailUploadStatus = document.getElementById('email-upload-status');

if (emailDropzone && emailFileInput) {
  emailDropzone.addEventListener('click', () => emailFileInput.click());

  emailDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    emailDropzone.classList.add('border-amber-400', 'bg-gray-900');
  });

  emailDropzone.addEventListener('dragleave', () => {
    emailDropzone.classList.remove('border-amber-400', 'bg-gray-900');
  });

  emailDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    emailDropzone.classList.remove('border-amber-400', 'bg-gray-900');
    if (e.dataTransfer.files.length > 0) {
      handleEmailFile(e.dataTransfer.files[0]);
    }
  });

  emailFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleEmailFile(e.target.files[0]);
    }
  });
}


async function handleEmailFile(file) {
  if (!emailUploadStatus) return;

  const allowedExtensions = ['.eml', '.msg', '.txt'];
  const lowerName = file.name.toLowerCase();
  if (!allowedExtensions.some(ext => lowerName.endsWith(ext))) {
    emailUploadStatus.classList.remove('hidden', 'text-green-400', 'text-gray-400');
    emailUploadStatus.classList.add('text-red-400');
    emailUploadStatus.textContent = 'Unsupported file type. Use .eml, .msg, or .txt.';
    return;
  }

  const maxBytes = 5 * 1024 * 1024;
  if (file.size > maxBytes) {
    emailUploadStatus.classList.remove('hidden', 'text-green-400', 'text-gray-400');
    emailUploadStatus.classList.add('text-red-400');
    emailUploadStatus.textContent = `File too large (${(file.size / 1024 / 1024).toFixed(1)}MB). Max 5MB.`;
    return;
  }

  emailUploadStatus.classList.remove('hidden', 'text-red-400', 'text-green-400');
  emailUploadStatus.classList.add('text-gray-400');
  emailUploadStatus.textContent = `Parsing ${file.name}...`;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/email-header/upload', {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: `HTTP ${res.status}`}));
      emailUploadStatus.classList.remove('text-gray-400', 'text-green-400');
      emailUploadStatus.classList.add('text-red-400');
      emailUploadStatus.textContent = `Upload failed: ${err.detail || res.status}`;
      return;
    }

    const data = await res.json();

    const headerEl = document.getElementById('email-header-input');
    const bodyEl = document.getElementById('email-body-input');
    if (headerEl) headerEl.value = data.raw_header || '';
    if (bodyEl) bodyEl.value = data.raw_body || '';

    const bodySection = document.getElementById('email-body-section');
    if (bodySection && data.raw_body) bodySection.open = true;

    emailUploadStatus.classList.remove('text-gray-400', 'text-red-400');
    emailUploadStatus.classList.add('text-green-400');
    emailUploadStatus.textContent = `Loaded ${data.filename}: ${data.header_bytes} bytes header, ${data.body_bytes} bytes body. File discarded. Click Analyze to continue.`;
  } catch (e) {
    console.error('email upload exception:', e);
    emailUploadStatus.classList.remove('text-gray-400', 'text-green-400');
    emailUploadStatus.classList.add('text-red-400');
    emailUploadStatus.textContent = `Upload error: ${e.message}`;
  } finally {
    if (emailFileInput) emailFileInput.value = '';
  }
}


// ---- Script Decoder ----

document.getElementById('decoder-clear-btn')?.addEventListener('click', () => {
  document.getElementById('decoder-code').value = '';
  const hintEl = document.getElementById('decoder-hint');
  if (hintEl) hintEl.value = '';
  const resultEl = document.getElementById('decoder-result');
  resultEl.classList.add('hidden');
  resultEl.innerHTML = '';
});

document.getElementById('decoder-btn')?.addEventListener('click', async () => {
  const codeEl = document.getElementById('decoder-code');
  const hintEl = document.getElementById('decoder-hint');
  const resultEl = document.getElementById('decoder-result');
  const btn = document.getElementById('decoder-btn');

  const code = (codeEl.value || '').trim();
  const hint = hintEl ? (hintEl.value || '').trim() : '';

  if (!code) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Paste some code first.</p>';
    return;
  }
  if (code.length < 20) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<p class="text-red-400 text-sm">Code too short (minimum 20 characters).</p>';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Decoding...';
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<p class="text-gray-400 text-sm animate-pulse">Calling Claude Haiku 4.5 to deobfuscate and analyze...</p>';

  try {
    const res = await fetch('/api/script-decoder/decode', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code: code, hint: hint || null}),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: `HTTP ${res.status}`}));
      resultEl.innerHTML = `<p class="text-red-400 text-sm">${escapeHtml(err.detail || `Request failed (${res.status})`)}</p>`;
      return;
    }

    const data = await res.json();
    resultEl.innerHTML = renderDecoderResult(data);
  } catch (e) {
    console.error('decoder exception:', e);
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Network error: ${escapeHtml(e.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Decode & Analyze';
  }
});


function renderDecoderResult(d) {
  const severityColor = {
    'critical': 'red',
    'high': 'red',
    'medium': 'amber',
    'low': 'yellow',
    'info': 'green',
  }[d.severity] || 'gray';

  const intentLabel = {
    'download_and_execute': 'Download & Execute',
    'credential_theft': 'Credential Theft',
    'persistence': 'Persistence',
    'lateral_movement': 'Lateral Movement',
    'ransomware': 'Ransomware',
    'reconnaissance': 'Reconnaissance',
    'defense_evasion': 'Defense Evasion',
    'command_and_control': 'Command & Control',
    'data_exfiltration': 'Data Exfiltration',
    'dropper': 'Dropper',
    'legitimate': 'Legitimate',
    'unclear': 'Unclear',
  }[d.intent] || (d.intent || 'unknown');

  let html = `
    <div class="bg-gray-900 border-l-4 border-${severityColor}-500 rounded p-5 mb-4">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-xs text-gray-500 uppercase tracking-widest">Verdict</h3>
        <span class="text-xs font-bold px-2 py-1 rounded bg-${severityColor}-900 text-${severityColor}-300 uppercase">${escapeHtml(d.severity || 'unknown')}</span>
      </div>
      <p class="text-lg font-bold text-${severityColor}-300 mb-2">${escapeHtml(intentLabel)}${d.malware_family ? ' &middot; ' + escapeHtml(d.malware_family) : ''}</p>
      <p class="text-sm text-gray-300 mb-3">${escapeHtml(d.summary || '')}</p>
      <p class="text-sm text-gray-400 leading-relaxed">${escapeHtml(d.explanation || '')}</p>
    </div>
  `;

  if (d.encoding_layers && d.encoding_layers.length > 0) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-4">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Encoding Layers</h3>
        <ol class="space-y-1 text-xs">
          ${d.encoding_layers.map((layer, i) => `
            <li class="flex gap-2">
              <span class="text-amber-400 font-bold">${i + 1}.</span>
              <span class="text-gray-300">${escapeHtml(layer)}</span>
            </li>
          `).join('')}
        </ol>
      </div>
    `;
  }

  if (d.deobfuscated_code) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider">Deobfuscated Code</h3>
          <button onclick="copyDecoderCode(this)" class="text-xs bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 px-2 py-0.5 rounded transition">Copy</button>
        </div>
        <pre class="bg-black border border-gray-800 rounded p-3 text-xs text-green-300 overflow-x-auto whitespace-pre-wrap break-words" id="decoder-deob-code">${escapeHtml(d.deobfuscated_code)}</pre>
      </div>
    `;
  }

  if (d.intermediate_stages && d.intermediate_stages.length > 0) {
    html += `
      <details class="bg-gray-900 border border-gray-800 rounded mb-4">
        <summary class="cursor-pointer px-5 py-3 text-sm font-bold text-gray-300 hover:text-amber-400 transition select-none">
          Intermediate Decoding Stages (${d.intermediate_stages.length})
        </summary>
        <div class="px-5 pb-5 space-y-3">
          ${d.intermediate_stages.map((stage, i) => `
            <div>
              <p class="text-xs text-gray-500 uppercase mb-1">Stage ${i + 1}: ${escapeHtml(stage.stage)}</p>
              <pre class="bg-black border border-gray-800 rounded p-3 text-xs text-amber-200 overflow-x-auto whitespace-pre-wrap break-words">${escapeHtml(stage.code)}</pre>
            </div>
          `).join('')}
        </div>
      </details>
    `;
  }

  const iocs = d.iocs || {};
  const iocCategories = [
    {key: 'urls', label: 'URLs', pivot: 'scanner'},
    {key: 'ips', label: 'IPs', pivot: 'ip'},
    {key: 'domains', label: 'Domains', pivot: 'domain'},
    {key: 'hashes', label: 'File hashes', pivot: 'sandbox'},
    {key: 'file_paths', label: 'File paths', pivot: null},
    {key: 'registry_keys', label: 'Registry keys', pivot: null},
    {key: 'commands', label: 'Commands', pivot: null},
  ];
  const hasIocs = iocCategories.some(cat => iocs[cat.key] && iocs[cat.key].length > 0);
  if (hasIocs) {
    html += '<div class="bg-gray-900 border border-gray-800 rounded p-5 mb-4"><h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Extracted IOCs</h3>';
    iocCategories.forEach(cat => {
      const items = iocs[cat.key] || [];
      if (!items.length) return;
      html += `<div class="mb-3"><p class="text-xs text-gray-500 uppercase mb-2">${escapeHtml(cat.label)} (${items.length})</p><div class="flex flex-wrap gap-2">`;
      items.forEach(item => {
        const display = item.length > 70 ? item.slice(0, 70) + '...' : item;
        if (cat.pivot === 'scanner') {
          html += `<button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition" onclick="pivotToScanner('${escapeAttr(item)}')">${escapeHtml(display)}</button>`;
        } else if (cat.pivot === 'ip') {
          html += `<button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition" onclick="pivotToIp('${escapeAttr(item)}')">${escapeHtml(item)}</button>`;
        } else if (cat.pivot === 'domain') {
          html += `<button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition" onclick="pivotToDomain('${escapeAttr(item)}')">${escapeHtml(item)}</button>`;
        } else if (cat.pivot === 'sandbox') {
          html += `<button class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-2 py-1 rounded transition" onclick="pivotToSandbox('${escapeAttr(item)}')">${escapeHtml(item.slice(0, 16) + '...')}</button>`;
        } else {
          html += `<span class="bg-gray-800 text-gray-300 text-xs font-mono px-2 py-1 rounded">${escapeHtml(display)}</span>`;
        }
      });
      html += '</div></div>';
    });
    html += '</div>';
  }

  if (d.mitre_techniques && d.mitre_techniques.length > 0) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-4">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">MITRE ATT&amp;CK Techniques</h3>
        <div class="flex flex-wrap gap-2">
          ${d.mitre_techniques.map(t => `
            <a href="https://attack.mitre.org/techniques/${escapeAttr(t.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer"
               class="bg-gray-800 hover:bg-amber-400 hover:text-gray-950 text-amber-300 text-xs font-mono px-3 py-1 rounded transition">${escapeHtml(t)}</a>
          `).join('')}
        </div>
      </div>
    `;
  }

  if (d.detection_suggestion) {
    html += `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 mb-4">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Detection Suggestion</h3>
        <p class="text-sm text-gray-300 leading-relaxed">${escapeHtml(d.detection_suggestion)}</p>
      </div>
    `;
  }

  if (d._usage) {
    const u = d._usage;
    html += `
      <p class="text-xs text-gray-700 mb-6 text-right font-mono">
        ${escapeHtml(u.model || 'LLM')}: ${u.input_tokens || 0} in + ${u.output_tokens || 0} out tokens
        ${u.cache_read_input_tokens ? `(${u.cache_read_input_tokens} cached)` : ''}
        ${d.cache_hit ? ' &middot; result from cache' : ''}
      </p>
    `;
  }

  return html;
}


function copyDecoderCode(btn) {
  const codeEl = document.getElementById('decoder-deob-code');
  if (!codeEl) return;
  navigator.clipboard.writeText(codeEl.textContent).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('bg-green-500', 'text-gray-950');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('bg-green-500', 'text-gray-950');
    }, 1500);
  });
}


function pivotToDomain(domain) {
  window.location.hash = '#domain';
  setTimeout(() => {
    const input = document.getElementById('domain-input');
    const btn = document.getElementById('domain-btn');
    if (input && btn) {
      input.value = domain;
      btn.click();
    }
  }, 200);
}


// ---- Prospect Tab ----

document.getElementById('prospect-btn').addEventListener('click', runProspectLookup);
document.getElementById('prospect-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runProspectLookup();
});

async function runProspectLookup() {
  const raw = document.getElementById('prospect-input').value.trim();
  const resultEl = document.getElementById('prospect-result');
  if (!raw) return;

  resultEl.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded p-5 animate-pulse space-y-3">
      <div class="h-4 bg-gray-800 rounded w-1/3"></div>
      <div class="h-3 bg-gray-800 rounded w-2/3"></div>
      <div class="h-3 bg-gray-800 rounded w-1/2"></div>
    </div>
    <div class="bg-gray-900 border border-gray-800 rounded p-5 animate-pulse space-y-3">
      <div class="h-4 bg-gray-800 rounded w-1/4"></div>
      <div class="h-3 bg-gray-800 rounded w-3/4"></div>
      <div class="h-16 bg-gray-800 rounded w-full"></div>
    </div>`;
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/prospect/${encodeURIComponent(raw)}`);
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${escapeHtml(data.detail || 'Unknown error')}</p>`;
      return;
    }
    renderProspectResult(resultEl, data);
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${escapeHtml(e.message)}</p>`;
  }
}

function renderProspectResult(el, data) {
  const s = data.sections || {};
  const errors = data.errors || [];
  const derived = data.derived || {};

  const cacheBadge = data.cached
    ? '<span class="text-xs text-gray-500">cached</span>'
    : '<span class="text-xs text-green-400">fresh</span>';

  el.innerHTML = `
    <div class="bg-gray-900 border border-gray-800 rounded p-4 flex items-center justify-between">
      <span class="brand-badge text-sm px-3 py-1">${escapeHtml(data.domain)}</span>
      ${cacheBadge}
    </div>
    ${renderAboutDomainCard(s.about_domain, errors, derived)}
    ${renderAdsTransparencyCard(s.ads_transparency, s.ads_transparency_historical, errors)}
    ${renderMetaAdPresenceCard(s.meta_page_search, s.meta_ads, errors)}
    ${renderHiringSignalsCard(s.google_jobs, derived, errors)}
    ${renderRecentNewsCard(s.google_news, derived, errors)}
    ${renderTimelineCard(s, errors)}
  `;
}

function renderAboutDomainCard(section, errors, derived) {
  const err = errors.find(e => e.section === 'about_domain');
  const errNote = err
    ? `<p class="text-xs text-gray-500 mb-3 italic">${escapeHtml(err.message)}</p>`
    : '';

  if (!section && (!derived || derived.confidence === 'low')) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Domain Identity</h3>
        ${errNote}
        <p class="text-sm text-gray-500">No identity data available for this domain.</p>
      </div>`;
  }

  const rows = [];
  const kg = (section && section.knowledge_graph) || {};
  const atr = (section && section.about_this_result) || {};
  const sfi = (section && section.site_first_indexed_by_google) || {};

  // Priority 1: knowledge_graph
  if (kg.title) rows.push({ label: 'Name', value: kg.title });
  if (kg.subtitle) rows.push({ label: 'Type', value: kg.subtitle });
  if (kg.description) rows.push({ label: 'Description', value: kg.description, wide: true });
  if (kg.source && kg.source.name) {
    rows.push({ label: 'Source', value: kg.source.name, link: kg.source.link });
  }

  // Priority 2: about_this_result fallback (for domains with no KG)
  if (!kg.title && atr.title) rows.push({ label: 'Name', value: atr.title });
  if (atr.source && atr.source.name) rows.push({ label: 'Source', value: atr.source.name });
  if (atr.displayed_link) rows.push({ label: 'URL', value: atr.displayed_link });

  // Priority 3: site_first_indexed_by_google
  if (sfi.text) rows.push({ label: 'Indexed', value: sfi.text, wide: true });

  // Fields that may appear at the top level of some responses
  if (section && section.displayed_link && !atr.displayed_link) {
    rows.push({ label: 'URL', value: section.displayed_link });
  }
  if (section && section.date) rows.push({ label: 'First indexed', value: section.date });

  // Trustpilot ratings
  const ratings = kg.ratings || [];
  const tp = ratings.find(r => r.source && r.source.toLowerCase().includes('trustpilot'));
  if (tp) {
    const tpStr = `${tp.rating}${tp.count ? ` (${tp.count.toLocaleString()} reviews)` : ''}`;
    rows.push({ label: 'Trustpilot', value: tpStr });
  }

  // Priority 4: resolved identity from resolver (ai_overview or domain fallback)
  // Used when KG, about_this_result, and site_first_indexed are all absent
  if (!rows.length && derived && derived.company_name && derived.confidence !== 'low') {
    rows.push({ label: 'Name', value: derived.company_name });
    if (derived.canonical_name && derived.canonical_name !== derived.company_name) {
      rows.push({ label: 'Legal name', value: derived.canonical_name });
    }
    const srcLabel = derived.source === 'ai_overview' ? 'AI overview' : 'Knowledge graph';
    rows.push({ label: 'Source', value: srcLabel });
  }

  const rowsHtml = rows.length
    ? `<div class="grid grid-cols-1 md:grid-cols-2 gap-4">${rows.map(r => `
        <div class="${r.wide ? 'md:col-span-2' : ''}">
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">${escapeHtml(r.label)}</p>
          ${r.link
            ? `<a href="${escapeAttr(r.link)}" target="_blank" rel="noopener noreferrer" class="text-sm text-amber-400 hover:text-amber-300">${escapeHtml(r.value)}</a>`
            : `<p class="text-sm text-gray-300">${escapeHtml(r.value)}</p>`}
        </div>`).join('')}</div>`
    : '<p class="text-sm text-gray-500">No structured identity data returned.</p>';

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Domain Identity</h3>
      ${errNote}
      ${rowsHtml}
    </div>`;
}

function _renderAdsTabPane(advId, advInfo, creatives, historical, total30d) {
  const advsCreatives = creatives.filter(c => (c.advertiser || {}).id === advId);
  const allFirstDates = advsCreatives.map(c => c.first_shown_datetime).filter(Boolean).sort();
  const allLastDates = advsCreatives.map(c => c.last_shown_datetime).filter(Boolean).sort();
  const firstShown = allFirstDates[0];
  const lastShown = allLastDates[allLastDates.length - 1];

  // historical is now {adv_id: {search_information: {...}}} dict
  const histData = (historical && typeof historical === 'object' && !Array.isArray(historical))
    ? (historical[advId] || null)
    : null;
  const histInfo = histData && histData.search_information;
  const histTotal = histInfo && histInfo.total_results;
  const legalName = histInfo && histInfo.legal_name;
  const basedIn = histInfo && histInfo.based_in;

  const meta = [];
  if (total30d !== undefined && total30d !== null) {
    meta.push({ label: 'Last 30 days (domain)', value: total30d.toLocaleString() + ' ads' });
  }
  if (advsCreatives.length) {
    meta.push({ label: `${escapeHtml(advInfo.name || advId)} (30d)`, value: advsCreatives.length + ' ads' });
  }
  if (histTotal) meta.push({ label: 'Historical total', value: histTotal.toLocaleString() + ' ads (all time)' });
  if (legalName && legalName !== advInfo.name) meta.push({ label: 'Legal name', value: legalName });
  if (basedIn || advInfo.location) meta.push({ label: 'Based in', value: basedIn || advInfo.location });
  if (advId) meta.push({ label: 'Advertiser ID', value: advId });
  if (firstShown) meta.push({ label: 'First shown (30d)', value: fmtPHT(firstShown) });
  if (lastShown) meta.push({ label: 'Last shown (30d)', value: fmtPHT(lastShown) });

  const metaHtml = meta.length
    ? `<div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4">${meta.map(m => `
        <div>
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">${escapeHtml(m.label)}</p>
          <p class="text-sm text-gray-300 font-mono">${escapeHtml(String(m.value))}</p>
        </div>`).join('')}</div>`
    : '';

  const thumbCreatives = advsCreatives.filter(c => c.image && c.image.link).slice(0, 12);
  const thumbsHtml = thumbCreatives.length
    ? `<div class="mb-4">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Sample creatives (${thumbCreatives.length})</p>
        <div class="flex flex-wrap gap-2">${thumbCreatives.map(c => `
          <div class="prospect-thumb-wrap">
            <img class="prospect-thumb rounded" src="${escapeAttr(c.image.link)}"
                 style="width:80px;height:50px;object-fit:cover;" loading="lazy"
                 alt="Ad creative" />
          </div>`).join('')}</div>
      </div>`
    : '';

  // Top ads table (Fix 4)
  const tableCreatives = [...advsCreatives]
    .sort((a, b) => (b.total_days_shown || 0) - (a.total_days_shown || 0));
  const showAll = tableCreatives.length <= 10;
  const tableRows = tableCreatives.map((c, i) => {
    const hidden = !showAll && i >= 10 ? ' class="ads-table-extra hidden"' : '';
    return `<tr${hidden}>
      <td class="py-1 px-2 text-gray-400">${c.position !== undefined ? c.position : i + 1}</td>
      <td class="py-1 px-2 text-gray-300 capitalize">${escapeHtml(c.format || '')}</td>
      <td class="py-1 px-2 text-gray-400 font-mono text-xs">${c.first_shown_datetime ? fmtPHT(c.first_shown_datetime) : ''}</td>
      <td class="py-1 px-2 text-gray-400 font-mono text-xs">${c.last_shown_datetime ? fmtPHT(c.last_shown_datetime) : ''}</td>
      <td class="py-1 px-2 text-gray-300 font-mono">${c.total_days_shown !== undefined && c.total_days_shown !== null ? c.total_days_shown : ''}</td>
      <td class="py-1 px-2 text-gray-400 text-xs truncate max-w-24">${escapeHtml(c.target_domain || '')}</td>
      <td class="py-1 px-2">${c.details_link ? `<a href="${escapeAttr(c.details_link)}" target="_blank" rel="noopener noreferrer" class="text-xs text-amber-400 hover:text-amber-300">view</a>` : ''}</td>
    </tr>`;
  }).join('');

  const expandBtn = (!showAll)
    ? `<button onclick="this.closest('.ads-table-wrap').querySelectorAll('.ads-table-extra').forEach(r=>r.classList.remove('hidden'));this.remove();"
               class="mt-2 text-xs text-gray-500 hover:text-gray-300">Show all ${tableCreatives.length} ads</button>`
    : '';

  const tableHtml = tableCreatives.length
    ? `<div class="ads-table-wrap mt-4">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Top ads (sorted by days shown)</p>
        <div class="overflow-x-auto">
          <table class="w-full text-xs border-collapse">
            <thead>
              <tr class="border-b border-gray-700">
                <th class="py-1 px-2 text-left text-gray-500 font-normal">#</th>
                <th class="py-1 px-2 text-left text-gray-500 font-normal">Format</th>
                <th class="py-1 px-2 text-left text-gray-500 font-normal">First shown</th>
                <th class="py-1 px-2 text-left text-gray-500 font-normal">Last shown</th>
                <th class="py-1 px-2 text-left text-gray-500 font-normal">Days</th>
                <th class="py-1 px-2 text-left text-gray-500 font-normal">Target</th>
                <th class="py-1 px-2 text-left text-gray-500 font-normal">Link</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-800">${tableRows}</tbody>
          </table>
        </div>
        ${expandBtn}
      </div>`
    : '';

  return metaHtml + thumbsHtml + tableHtml;
}

function renderAdsTransparencyCard(section, historical, errors) {
  const err = errors.find(e => e.section === 'ads_transparency');
  const errNote = err
    ? `<p class="text-xs text-gray-500 mb-3 italic">${escapeHtml(err.message)}</p>`
    : '';

  if (!section) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Google Ads Activity</h3>
        ${errNote}
        <p class="text-sm text-gray-500">No ad activity data available.</p>
      </div>`;
  }

  const creatives = section.ad_creatives || [];
  const total30d = section.search_information && section.search_information.total_results;

  if (!creatives.length) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Google Ads Activity</h3>
        ${errNote}
        <p class="text-sm text-gray-500">No Google Ads activity detected in the last 30 days.</p>
      </div>`;
  }

  // Advertisers array added by service enrichment
  const advertisers = section._advertisers || [];

  if (advertisers.length <= 1) {
    // Single advertiser: simple layout
    const advInfo = advertisers[0] || (creatives[0] && creatives[0].advertiser) || {};
    const advId = advInfo.id || '';
    const paneHtml = _renderAdsTabPane(advId, advInfo, creatives, historical, total30d);
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Google Ads Activity</h3>
        ${errNote}
        ${paneHtml}
      </div>`;
  }

  // Multiple advertisers: tab selector
  const selectorNote = `<p class="text-xs text-gray-500 mb-3">This domain runs ads under ${advertisers.length} advertiser accounts. Select to view each.</p>`;

  const tabBtns = advertisers.map((adv, i) => {
    const active = i === 0;
    const cls = active
      ? 'ads-tab-btn text-xs px-3 py-1 rounded bg-amber-400 text-black font-medium'
      : 'ads-tab-btn text-xs px-3 py-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600';
    const label = escapeHtml((adv.name || adv.id).slice(0, 40));
    const cnt = `(${adv.count})`;
    return `<button class="${cls}" data-target="ads-pane-${escapeAttr(adv.id)}"
      onclick="(function(btn){
        var cont=btn.closest('.ads-tab-container');
        cont.querySelectorAll('.ads-tab-pane').forEach(function(p){p.classList.add('hidden')});
        cont.querySelectorAll('.ads-tab-btn').forEach(function(b){
          b.classList.remove('bg-amber-400','text-black','font-medium');
          b.classList.add('bg-gray-700','text-gray-300');
        });
        document.getElementById(btn.dataset.target).classList.remove('hidden');
        btn.classList.remove('bg-gray-700','text-gray-300');
        btn.classList.add('bg-amber-400','text-black','font-medium');
      })(this)">${label} ${escapeHtml(cnt)}</button>`;
  }).join('');

  const tabPanes = advertisers.map((adv, i) => {
    const hidden = i === 0 ? '' : ' hidden';
    const paneHtml = _renderAdsTabPane(adv.id, adv, creatives, historical, total30d);
    return `<div id="ads-pane-${escapeAttr(adv.id)}" class="ads-tab-pane${hidden}">${paneHtml}</div>`;
  }).join('');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Google Ads Activity</h3>
      ${errNote}
      <div class="ads-tab-container">
        ${selectorNote}
        <div class="flex flex-wrap gap-2 mb-4">${tabBtns}</div>
        ${tabPanes}
      </div>
    </div>`;
}

function renderMetaAdPresenceCard(pageSearch, metaAds, errors) {
  const err1 = errors.find(e => e.section === 'meta_page_search');
  const err2 = errors.find(e => e.section === 'meta_ads');
  const errNote = [err1, err2].filter(Boolean).map(e =>
    `<p class="text-xs text-gray-500 mb-2 italic">${escapeHtml(e.message)}</p>`
  ).join('');

  const allPages = (pageSearch && pageSearch.page_results) || [];
  // Use the service-selected page (identity-filtered) when available
  const selectedPage = pageSearch && pageSearch._selected_page;
  // Show selected page prominently, then other matching pages
  const pages = selectedPage
    ? [selectedPage, ...allPages.filter(p => p.page_id !== selectedPage.page_id)].slice(0, 5)
    : [...allPages].sort((a, b) => (b.likes || 0) - (a.likes || 0)).slice(0, 5);
  const ads = (metaAds && metaAds.ads) || [];

  // When service filtered all pages out, show empty state for pages section
  const pagesFiltered = pageSearch && pageSearch._selected_page === null && allPages.length > 0;

  if (!pages.length && !ads.length) {
    const note = pagesFiltered
      ? `<p class="text-sm text-gray-500 italic">No Meta pages matched the company identity. ${allPages.length} page(s) were returned but did not match.</p>`
      : '<p class="text-sm text-gray-500">No Meta advertising presence detected.</p>';
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Meta Ad Presence</h3>
        ${errNote}
        ${note}
      </div>`;
  }

  const totalMetaAds = (metaAds && metaAds.search_information && metaAds.search_information.total_results) || ads.length;
  const activeAds = ads.filter(a => a.is_active).length;

  const sortedPages = pages;

  const verifiedBadge = v => v === 'BLUE_VERIFIED'
    ? '<span class="text-xs text-blue-400 ml-1">verified</span>'
    : '';

  const filteredNote = pagesFiltered
    ? `<p class="text-xs text-gray-500 mb-3 italic">No Meta pages matched the company identity after filtering.</p>`
    : '';

  const pagesHtml = sortedPages.length
    ? `<div class="mb-4">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Facebook pages</p>
        <div class="space-y-2">${sortedPages.map(p => `
          <div class="flex items-center gap-3">
            ${p.image_uri ? `<img src="${escapeAttr(p.image_uri)}" class="w-8 h-8 rounded-full flex-shrink-0 bg-gray-800" loading="lazy" alt="" onerror="this.style.display='none'">` : '<div class="w-8 h-8 rounded-full bg-gray-800 flex-shrink-0"></div>'}
            <div class="min-w-0">
              <p class="text-sm text-gray-200 truncate">${escapeHtml(p.name || '')}${verifiedBadge(p.verification)}</p>
              <p class="text-xs text-gray-500">${p.category ? escapeHtml(p.category) + ' · ' : ''}${p.likes ? p.likes.toLocaleString() + ' likes' : ''}${p.ig_followers ? ' · ' + p.ig_followers.toLocaleString() + ' IG followers' : ''}</p>
            </div>
          </div>`).join('')}</div>
      </div>`
    : filteredNote;

  const adsSummaryHtml = (totalMetaAds || activeAds)
    ? `<div class="grid grid-cols-2 gap-4 mb-4">
        ${totalMetaAds ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Total ads (library)</p><p class="text-sm text-gray-300 font-mono">${totalMetaAds.toLocaleString()}</p></div>` : ''}
        ${activeAds ? `<div><p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Active (snapshot)</p><p class="text-sm text-gray-300 font-mono">${activeAds}</p></div>` : ''}
      </div>`
    : '';

  const thumbUrls = ads.flatMap(a => {
    const snap = a.snapshot || {};
    return (snap.images || []).map(img => img.original_image_url).filter(Boolean);
  }).slice(0, 6);

  const thumbsHtml = thumbUrls.length
    ? `<div>
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Sample Meta creatives (${thumbUrls.length})</p>
        <div class="flex flex-wrap gap-2">${thumbUrls.map(url => `
          <div class="prospect-thumb-wrap">
            <img class="prospect-thumb rounded" src="${escapeAttr(url)}"
                 style="width:80px;height:50px;object-fit:cover;" loading="lazy"
                 alt="Meta ad creative" onerror="this.parentElement.style.display='none'" />
          </div>`).join('')}</div>
      </div>`
    : '';

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Meta Ad Presence</h3>
      ${errNote}
      ${pagesHtml}
      ${adsSummaryHtml}
      ${thumbsHtml}
    </div>`;
}

function renderHiringSignalsCard(jobsSection, derived, errors) {
  const err = errors.find(e => e.section === 'google_jobs');
  const errNote = err
    ? `<p class="text-xs text-gray-500 mb-3 italic">${escapeHtml(err.message)}</p>`
    : '';

  const confidence = (derived && derived.confidence) || 'high';

  // Low confidence: jobs call was skipped to avoid garbage results
  if (confidence === 'low') {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Hiring Signals</h3>
        <p class="text-sm text-gray-500">Company identity could not be reliably resolved. Skipping hiring signals to avoid unrelated results.</p>
      </div>`;
  }

  const jobs = (jobsSection && jobsSection.jobs) || [];

  if (!jobs.length) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Hiring Signals</h3>
        ${errNote}
        <p class="text-sm text-gray-500">No open roles found.</p>
      </div>`;
  }

  const displayJobs = jobs;

  // Location frequency
  const locMap = {};
  displayJobs.forEach(j => {
    const loc = j.location || 'Location unknown';
    locMap[loc] = (locMap[loc] || 0) + 1;
  });
  const locEntries = Object.entries(locMap).sort((a, b) => b[1] - a[1]);
  const maxLocCount = locEntries.length ? locEntries[0][1] : 1;

  const barsHtml = locEntries.length > 3
    ? `<div class="mt-3 space-y-1">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Roles by location</p>
        ${locEntries.slice(0, 8).map(([loc, count]) => `
          <div class="flex items-center gap-2">
            <span class="text-xs text-gray-400 w-32 truncate" title="${escapeAttr(loc)}">${escapeHtml(loc)}</span>
            <div class="flex-1 bg-gray-800 rounded h-2">
              <div class="bg-amber-400 rounded h-2" style="width:${Math.round(count / maxLocCount * 100)}%"></div>
            </div>
            <span class="text-xs text-gray-500 w-4 text-right">${count}</span>
          </div>`).join('')}
      </div>`
    : locEntries.length
      ? `<p class="text-sm text-gray-300 mt-2">${locEntries.map(([loc, n]) => `${escapeHtml(loc)} (${n})`).join(', ')}</p>`
      : '';

  const uniqueTitles = [...new Set(displayJobs.map(j => j.title).filter(Boolean))].slice(0, 6);
  const titlesHtml = uniqueTitles.length
    ? `<div class="mb-1">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-2">Open roles (sample)</p>
        <div class="flex flex-wrap gap-2">${uniqueTitles.map(t => `
          <span class="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">${escapeHtml(t)}</span>`).join('')}
        </div>
      </div>`
    : '';

  const totalHtml = `<p class="text-sm text-gray-300 mb-3"><span class="font-mono text-amber-400">${displayJobs.length}</span> open role${displayJobs.length !== 1 ? 's' : ''} found</p>`;

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Hiring Signals</h3>
      ${errNote}
      ${totalHtml}
      ${titlesHtml}
      ${barsHtml}
    </div>`;
}

function renderRecentNewsCard(newsSection, derived, errors) {
  const err = errors.find(e => e.section === 'google_news');
  const errNote = err
    ? `<p class="text-xs text-gray-500 mb-3 italic">${escapeHtml(err.message)}</p>`
    : '';

  const confidence = (derived && derived.confidence) || 'high';
  const scopeNote = confidence === 'low'
    ? `<p class="text-xs text-amber-600 mb-3">Company identity could not be reliably resolved from the domain. Domain-scoped news only.</p>`
    : '';

  const articles = (newsSection && newsSection.organic_results) || [];

  if (!articles.length) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Recent News</h3>
        ${errNote}
        ${scopeNote}
        <p class="text-sm text-gray-500">No recent news articles found.</p>
      </div>`;
  }

  const articlesHtml = articles.slice(0, 8).map(a => `
    <div class="flex items-start gap-3 py-2 border-b border-gray-800 last:border-0">
      ${a.favicon
        ? `<img src="${escapeAttr(a.favicon)}" alt="" class="w-4 h-4 mt-0.5 flex-shrink-0" onerror="this.style.display='none'" loading="lazy">`
        : '<div class="w-4 h-4 flex-shrink-0"></div>'}
      <div class="min-w-0">
        <a href="${escapeAttr(a.link)}" target="_blank" rel="noopener noreferrer"
           class="text-sm text-amber-400 hover:text-amber-300 leading-tight block">${escapeHtml(a.title)}</a>
        <p class="text-xs text-gray-500 mt-0.5">${escapeHtml(a.source || '')}${a.date ? ' · ' + escapeHtml(a.date) : ''}</p>
        ${a.snippet ? `<p class="text-xs text-gray-400 mt-1">${escapeHtml(a.snippet.slice(0, 160))}${a.snippet.length > 160 ? '...' : ''}</p>` : ''}
      </div>
    </div>`).join('');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Recent News</h3>
      ${errNote}
      ${scopeNote}
      ${articlesHtml}
    </div>`;
}

function renderTimelineCard(sections, errors) {
  const events = [];

  const ads30d = sections.ads_transparency;
  if (ads30d && ads30d.ad_creatives && ads30d.ad_creatives.length) {
    const firsts = ads30d.ad_creatives.map(c => c.first_shown_datetime).filter(Boolean).sort();
    const lasts = ads30d.ad_creatives.map(c => c.last_shown_datetime).filter(Boolean).sort();
    if (firsts[0]) events.push({ date: firsts[0], label: 'First Google Ad (30-day window)', type: 'ads' });
    const lastLast = lasts[lasts.length - 1];
    if (lastLast && lastLast !== firsts[0]) events.push({ date: lastLast, label: 'Latest Google Ad (30-day window)', type: 'ads' });
  }

  const metaAds = sections.meta_ads;
  if (metaAds && metaAds.ads && metaAds.ads.length) {
    const starts = metaAds.ads.map(a => a.start_date).filter(Boolean).sort();
    const ends = metaAds.ads.map(a => a.end_date).filter(Boolean).sort();
    if (starts[0]) events.push({ date: starts[0], label: 'First Meta Ad (library snapshot)', type: 'meta' });
    const lastEnd = ends[ends.length - 1];
    if (lastEnd && lastEnd !== starts[0]) events.push({ date: lastEnd, label: 'Latest Meta Ad end date', type: 'meta' });
  }

  const news = sections.google_news;
  if (news && news.organic_results) {
    news.organic_results.forEach(a => {
      if (a.iso_date) {
        events.push({ date: a.iso_date, label: `${a.title} (${a.source || 'news'})`, type: 'news', link: a.link });
      }
    });
  }

  if (!events.length) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wide">Activity Timeline</h3>
        <p class="text-sm text-gray-500">No dated events to display.</p>
      </div>`;
  }

  events.sort((a, b) => b.date.localeCompare(a.date));

  const dotColors = { ads: 'bg-amber-400', meta: 'bg-blue-400', news: 'bg-gray-500' };

  const eventsHtml = events.map(ev => {
    const dot = dotColors[ev.type] || 'bg-gray-500';
    const label = ev.link
      ? `<a href="${escapeAttr(ev.link)}" target="_blank" rel="noopener noreferrer" class="text-sm text-amber-400 hover:text-amber-300">${escapeHtml(ev.label)}</a>`
      : `<p class="text-sm text-gray-300">${escapeHtml(ev.label)}</p>`;
    return `
      <div class="relative pl-5">
        <div class="absolute left-0 top-1.5 w-2.5 h-2.5 ${dot} rounded-full border-2 border-gray-950 flex-shrink-0"></div>
        <p class="text-xs text-gray-500 mb-0.5">${escapeHtml(fmtPHT(ev.date))}</p>
        ${label}
      </div>`;
  }).join('');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 mb-4 uppercase tracking-wide">Activity Timeline</h3>
      <div class="border-l-2 border-gray-700 pl-4 space-y-3">
        ${eventsHtml}
      </div>
    </div>`;
}


// Load both on page ready (they fire in parallel)
loadThreatPulse();
loadLandingNews();

// ---- Image Reverse Search Tab ----

(function () {
  const urlModeBtn = document.getElementById('img-mode-url');
  const uploadModeBtn = document.getElementById('img-mode-upload');
  const urlMode = document.getElementById('img-url-mode');
  const uploadMode = document.getElementById('img-upload-mode');
  const resultEl = document.getElementById('image-result');
  const dropzone = document.getElementById('img-dropzone');
  const fileInput = document.getElementById('img-file-input');
  const previewArea = document.getElementById('img-preview-area');
  const previewThumb = document.getElementById('img-preview-thumb');
  const previewName = document.getElementById('img-preview-name');
  const previewSize = document.getElementById('img-preview-size');
  let _selectedFile = null;

  function switchMode(mode) {
    if (mode === 'url') {
      urlModeBtn.classList.add('bg-amber-400', 'text-gray-950', 'font-bold');
      urlModeBtn.classList.remove('text-gray-400');
      uploadModeBtn.classList.remove('bg-amber-400', 'text-gray-950', 'font-bold');
      uploadModeBtn.classList.add('text-gray-400');
      urlMode.classList.remove('hidden');
      uploadMode.classList.add('hidden');
    } else {
      uploadModeBtn.classList.add('bg-amber-400', 'text-gray-950', 'font-bold');
      uploadModeBtn.classList.remove('text-gray-400');
      urlModeBtn.classList.remove('bg-amber-400', 'text-gray-950', 'font-bold');
      urlModeBtn.classList.add('text-gray-400');
      uploadMode.classList.remove('hidden');
      urlMode.classList.add('hidden');
    }
  }

  if (urlModeBtn) urlModeBtn.addEventListener('click', () => switchMode('url'));
  if (uploadModeBtn) uploadModeBtn.addEventListener('click', () => switchMode('upload'));

  function showFilePreview(file) {
    _selectedFile = file;
    const reader = new FileReader();
    reader.onload = e => {
      if (previewThumb) previewThumb.src = e.target.result;
    };
    reader.readAsDataURL(file);
    if (previewName) previewName.textContent = file.name;
    if (previewSize) previewSize.textContent = (file.size / 1024).toFixed(1) + ' KB';
    if (previewArea) previewArea.classList.remove('hidden');
  }

  if (dropzone) {
    dropzone.addEventListener('click', () => fileInput && fileInput.click());
    dropzone.addEventListener('dragover', e => {
      e.preventDefault();
      dropzone.classList.add('border-amber-400');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('border-amber-400'));
    dropzone.addEventListener('drop', e => {
      e.preventDefault();
      dropzone.classList.remove('border-amber-400');
      const file = e.dataTransfer.files[0];
      if (file) showFilePreview(file);
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files[0]) showFilePreview(fileInput.files[0]);
    });
  }

  function imgSkeleton() {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5 animate-pulse space-y-3">
        <div class="h-4 bg-gray-800 rounded w-1/3"></div>
        <div class="h-48 bg-gray-800 rounded"></div>
      </div>
      <div class="bg-gray-900 border border-gray-800 rounded p-5 animate-pulse space-y-3">
        <div class="h-4 bg-gray-800 rounded w-1/4"></div>
        <div class="grid grid-cols-3 gap-3">
          ${[1,2,3,4,5,6].map(() => '<div class="h-24 bg-gray-800 rounded"></div>').join('')}
        </div>
      </div>
      <div class="bg-gray-900 border border-gray-800 rounded p-5 animate-pulse space-y-3">
        <div class="h-4 bg-gray-800 rounded w-1/4"></div>
        <div class="h-32 bg-gray-800 rounded"></div>
      </div>`;
  }

  async function runImageSearch(imageUrl, isUpload) {
    if (!resultEl) return;
    resultEl.innerHTML = imgSkeleton();
    resultEl.classList.remove('hidden');

    try {
      const body = isUpload ? { signed_url: imageUrl } : { image_url: imageUrl };
      const res = await fetch('/api/image/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        resultEl.innerHTML = `<p class="text-red-400 text-sm">Error: ${escapeHtml(data.detail || 'Unknown error')}</p>`;
        return;
      }
      renderImageResult(resultEl, data, imageUrl);
    } catch (e) {
      resultEl.innerHTML = `<p class="text-red-400 text-sm">Request failed: ${escapeHtml(e.message)}</p>`;
    }
  }

  const analyzeBtn = document.getElementById('img-analyze-btn');
  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      const url = (document.getElementById('img-url-input') || {}).value.trim();
      if (url) runImageSearch(url, false);
    });
  }

  const urlInput = document.getElementById('img-url-input');
  if (urlInput) {
    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') analyzeBtn && analyzeBtn.click();
    });
  }

  const uploadAnalyzeBtn = document.getElementById('img-upload-analyze-btn');
  if (uploadAnalyzeBtn) {
    uploadAnalyzeBtn.addEventListener('click', async () => {
      if (!_selectedFile) return;
      uploadAnalyzeBtn.disabled = true;
      uploadAnalyzeBtn.textContent = 'Uploading...';
      try {
        const form = new FormData();
        form.append('file', _selectedFile);
        const res = await fetch('/api/image/upload', { method: 'POST', body: form });
        const data = await res.json();
        if (!res.ok) {
          if (resultEl) resultEl.innerHTML = `<p class="text-red-400 text-sm">Upload failed: ${escapeHtml(data.detail || 'Unknown error')}</p>`;
          resultEl && resultEl.classList.remove('hidden');
          return;
        }
        await runImageSearch(data.signed_url, true);
      } catch (e) {
        if (resultEl) {
          resultEl.innerHTML = `<p class="text-red-400 text-sm">Upload failed: ${escapeHtml(e.message)}</p>`;
          resultEl.classList.remove('hidden');
        }
      } finally {
        uploadAnalyzeBtn.disabled = false;
        uploadAnalyzeBtn.textContent = 'Analyze';
      }
    });
  }
})();


function renderImageResult(el, data, imageUrl) {
  const s = data.sections || {};
  const errors = data.errors || [];
  const cacheBadge = data.cached
    ? '<span class="text-xs text-gray-500">cached</span>'
    : '<span class="text-xs text-green-400">fresh</span>';

  el.innerHTML = [
    renderImagePreviewCard(imageUrl, cacheBadge),
    renderGoogleLensCard(s.google_lens, errors),
    renderYandexCard(s.yandex, errors),
    renderCrossSourceCard(s.cross_source_domains),
    renderExifCard(s.exif),
  ].join('');
}


function renderImagePreviewCard(imageUrl, cacheBadge) {
  const safe = escapeAttr(imageUrl);
  const display = escapeHtml(imageUrl.length > 80 ? imageUrl.slice(0, 80) + '...' : imageUrl);
  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide">Query Image</h3>
        ${cacheBadge}
      </div>
      <div class="flex gap-4 items-start">
        <img src="${safe}" alt="Query image"
             class="max-w-xs max-h-64 rounded border border-gray-700 object-contain bg-gray-800"
             onerror="this.style.display='none'" />
        <div class="min-w-0">
          <p class="text-xs text-gray-500 mb-1">Source URL</p>
          <a href="${safe}" target="_blank" rel="noopener noreferrer"
             class="text-amber-400 hover:text-amber-300 text-xs break-all font-mono">${display}</a>
        </div>
      </div>
    </div>`;
}


function renderGoogleLensCard(section, errors) {
  const err = errors.find(e => e.section === 'google_lens');
  const errNote = err
    ? `<p class="text-xs text-gray-500 mb-3 italic">${escapeHtml(err.message)}</p>`
    : '';

  const matches = (section && section.visual_matches) || [];
  const related = (section && section.related_searches) || [];
  const hasError = section && section.error && !matches.length;

  const matchesHtml = matches.slice(0, 12).map(m => {
    const thumb = m.thumbnail || (m.image && m.image.link) || '';
    const title = escapeHtml(m.title || m.source || 'Result');
    const link = escapeAttr(m.link || '#');
    const source = escapeHtml(m.source || '');
    const price = m.price ? `<span class="text-green-400 text-xs">${escapeHtml(m.price)}</span>` : '';
    const stock = m.in_stock !== undefined
      ? `<span class="text-xs ${m.in_stock ? 'text-green-500' : 'text-gray-500'}">${m.in_stock ? 'In stock' : 'Out of stock'}</span>`
      : '';
    return `
      <a href="${link}" target="_blank" rel="noopener noreferrer"
         class="block bg-gray-800 rounded p-2 hover:bg-gray-700 transition">
        ${thumb ? `<img src="${escapeAttr(thumb)}" alt="" class="w-full h-24 object-cover rounded mb-2" onerror="this.style.display='none'" />` : '<div class="w-full h-24 bg-gray-700 rounded mb-2 flex items-center justify-center text-gray-600 text-xs">No preview</div>'}
        <p class="text-xs text-gray-300 leading-tight mb-1 line-clamp-2">${title}</p>
        <p class="text-xs text-gray-500">${source}</p>
        ${price} ${stock}
      </a>`;
  }).join('');

  const relatedHtml = related.map(r => {
    const link = escapeAttr(r.link || '#');
    return `<a href="${link}" target="_blank" rel="noopener noreferrer"
               class="text-xs bg-gray-800 px-3 py-1 rounded-full text-gray-300 hover:text-white hover:bg-gray-700 transition">${escapeHtml(r.title || '')}</a>`;
  }).join('');

  const body = matches.length
    ? `<div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 mb-4">${matchesHtml}</div>
       ${relatedHtml ? `<div class="flex flex-wrap gap-2"><p class="text-xs text-gray-500 w-full mb-1">Related searches</p>${relatedHtml}</div>` : ''}`
    : (hasError
        ? `<p class="text-sm text-gray-500">${escapeHtml(section.error)}</p>`
        : '<p class="text-sm text-gray-500">No visual matches returned.</p>');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide mb-3">Google Lens Results</h3>
      ${errNote}
      ${body}
    </div>`;
}


function renderYandexCard(section, errors) {
  const err = errors.find(e => e.section === 'yandex');
  const errNote = err
    ? `<p class="text-xs text-gray-500 mb-3 italic">${escapeHtml(err.message)}</p>`
    : '';

  if (!section) {
    return `
      <div class="bg-gray-900 border border-gray-800 rounded p-5">
        <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide mb-3">Yandex Reverse Image</h3>
        ${errNote}
        <p class="text-sm text-gray-500">No Yandex results.</p>
      </div>`;
  }

  const imageSizes = section.image_sizes || {};
  const allSizes = [];
  for (const [group, items] of Object.entries(imageSizes)) {
    for (const item of (items || [])) {
      if (item.size && item.link) allSizes.push(item);
    }
  }

  function parsePx(sizeStr) {
    const m = sizeStr.replace(/\xd7/g, 'x').match(/(\d+)\s*x\s*(\d+)/i);
    return m ? parseInt(m[1]) * parseInt(m[2]) : 0;
  }

  allSizes.sort((a, b) => parsePx(b.size) - parsePx(a.size));

  const sizesHtml = allSizes.length
    ? `<div class="mb-5">
        <h4 class="text-xs font-bold text-amber-400 uppercase tracking-wide mb-2">Image Sizes Found (${allSizes.length})</h4>
        <div class="overflow-x-auto">
          <table class="w-full text-xs">
            <thead><tr class="text-gray-500 border-b border-gray-800">
              <th class="text-left py-1 pr-4">Resolution</th>
              <th class="text-left py-1">Source</th>
            </tr></thead>
            <tbody>
              ${allSizes.slice(0, 20).map(item => {
                const domain = (() => { try { return new URL(item.link).hostname.replace(/^www\./, ''); } catch { return item.link.slice(0,30); } })();
                return `<tr class="border-b border-gray-800 hover:bg-gray-800">
                  <td class="py-1.5 pr-4 text-gray-200 font-mono font-bold">${escapeHtml(item.size)}</td>
                  <td class="py-1.5"><a href="${escapeAttr(item.link)}" target="_blank" rel="noopener noreferrer" class="text-amber-400 hover:text-amber-300">${escapeHtml(domain)}</a></td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>`
    : '';

  const visualMatches = section.visual_matches || [];
  const similarImages = section.similar_images || [];
  const related = section.related_searches || [];

  const vmHtml = visualMatches.slice(0, 8).map(m => {
    const thumb = m.thumbnail || '';
    const title = escapeHtml(m.title || m.source || '');
    const link = escapeAttr(m.link || '#');
    const source = escapeHtml(m.source || '');
    return `
      <a href="${link}" target="_blank" rel="noopener noreferrer"
         class="block bg-gray-800 rounded p-2 hover:bg-gray-700 transition">
        ${thumb ? `<img src="${escapeAttr(thumb)}" alt="" class="w-full h-20 object-cover rounded mb-1" onerror="this.style.display='none'" />` : '<div class="w-full h-20 bg-gray-700 rounded mb-1"></div>'}
        <p class="text-xs text-gray-300 leading-tight line-clamp-2">${title}</p>
        <p class="text-xs text-gray-500">${source}</p>
      </a>`;
  }).join('');

  const similarHtml = similarImages.slice(0, 8).map(m => {
    const thumb = m.thumbnail || '';
    const link = escapeAttr(m.link || '#');
    return thumb
      ? `<a href="${link}" target="_blank" rel="noopener noreferrer"><img src="${escapeAttr(thumb)}" alt="Similar" class="w-full h-20 object-cover rounded hover:opacity-80 transition" onerror="this.style.display='none'" /></a>`
      : '';
  }).filter(Boolean).join('');

  const relatedHtml = related.map(r =>
    `<a href="${escapeAttr(r.link || '#')}" target="_blank" rel="noopener noreferrer"
        class="text-xs bg-gray-800 px-3 py-1 rounded-full text-gray-300 hover:text-white hover:bg-gray-700 transition">${escapeHtml(r.title || '')}</a>`
  ).join('');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide mb-3">Yandex Reverse Image</h3>
      ${errNote}
      ${sizesHtml}
      ${visualMatches.length ? `<h4 class="text-xs font-bold text-gray-400 uppercase tracking-wide mb-2">Visual Matches (${visualMatches.length})</h4><div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">${vmHtml}</div>` : ''}
      ${similarImages.length ? `<h4 class="text-xs font-bold text-gray-400 uppercase tracking-wide mb-2">Similar Images</h4><div class="grid grid-cols-4 sm:grid-cols-8 gap-2 mb-4">${similarHtml}</div>` : ''}
      ${relatedHtml ? `<div class="flex flex-wrap gap-2"><p class="text-xs text-gray-500 w-full mb-1">Related searches</p>${relatedHtml}</div>` : ''}
      ${!sizesHtml && !visualMatches.length && !similarImages.length ? '<p class="text-sm text-gray-500">No results returned.</p>' : ''}
    </div>`;
}


function renderCrossSourceCard(domains) {
  const list = domains || [];
  const signal = list.length >= 3
    ? '<p class="text-xs text-green-400 mb-3">Strong signal: 3 or more overlapping sources found across both engines.</p>'
    : '';
  const body = list.length
    ? `${signal}<div class="flex flex-wrap gap-2">${list.map(d => `<span class="text-xs bg-gray-800 px-3 py-1 rounded text-gray-300 font-mono">${escapeHtml(d)}</span>`).join('')}</div>`
    : '<p class="text-sm text-gray-500">No overlapping sources found across engines.</p>';
  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide mb-3">Cross-Source Corroboration</h3>
      ${body}
    </div>`;
}


function renderExifCard(exif) {
  if (!exif || !Object.keys(exif).length) return '';
  const hasGps = exif.gps && typeof exif.gps.lat === 'number';
  const gpsWarning = hasGps
    ? `<div class="bg-yellow-950 border border-yellow-700 rounded p-3 mb-4 flex items-center gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-yellow-400 flex-shrink-0"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <p class="text-xs text-yellow-300">This image contains embedded location data.</p>
      </div>`
    : '';

  const rows = [];
  if (exif.camera_make || exif.camera_model) {
    rows.push({ label: 'Camera', value: [exif.camera_make, exif.camera_model].filter(Boolean).join(' ') });
  }
  if (exif.datetime_original) rows.push({ label: 'Date taken', value: exif.datetime_original });
  if (exif.software) rows.push({ label: 'Software', value: exif.software });
  if (exif.orientation) rows.push({ label: 'Orientation', value: String(exif.orientation) });
  if (exif.width && exif.height) rows.push({ label: 'Dimensions', value: `${exif.width} x ${exif.height} px` });
  if (hasGps) {
    const lat = exif.gps.lat.toFixed(6);
    const lon = exif.gps.lon.toFixed(6);
    const alt = exif.gps.altitude !== undefined ? ` (alt: ${exif.gps.altitude}m)` : '';
    const mapUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}&zoom=15`;
    rows.push({
      label: 'GPS',
      value: `<a href="${escapeAttr(mapUrl)}" target="_blank" rel="noopener noreferrer" class="text-amber-400 hover:text-amber-300">${lat}, ${lon}${escapeHtml(alt)}</a>`,
      raw: true,
    });
  }

  const rowsHtml = rows.map(r =>
    `<tr class="border-b border-gray-800">
      <td class="py-1.5 pr-6 text-xs text-gray-500 whitespace-nowrap">${escapeHtml(r.label)}</td>
      <td class="py-1.5 text-xs text-gray-300">${r.raw ? r.value : escapeHtml(r.value)}</td>
    </tr>`
  ).join('');

  return `
    <div class="bg-gray-900 border border-gray-800 rounded p-5">
      <h3 class="text-sm font-bold text-gray-300 uppercase tracking-wide mb-3">EXIF Data</h3>
      ${gpsWarning}
      <table class="w-full"><tbody>${rowsHtml}</tbody></table>
    </div>`;
}

// ---- Privacy Policy Modal ----

const privacyModal = document.getElementById('privacy-modal');
const openPrivacyBtn = document.getElementById('open-privacy-policy');
const closePrivacyBtnX = document.getElementById('close-privacy-policy');
const closePrivacyBtnFooter = document.getElementById('close-privacy-policy-btn');

function openPrivacyPolicy(e) {
  if (e) e.preventDefault();
  if (privacyModal) {
    privacyModal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }
}

function closePrivacyPolicy() {
  if (privacyModal) {
    privacyModal.classList.add('hidden');
    document.body.style.overflow = '';
  }
}

if (openPrivacyBtn) openPrivacyBtn.addEventListener('click', openPrivacyPolicy);
if (closePrivacyBtnX) closePrivacyBtnX.addEventListener('click', closePrivacyPolicy);
if (closePrivacyBtnFooter) closePrivacyBtnFooter.addEventListener('click', closePrivacyPolicy);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && privacyModal && !privacyModal.classList.contains('hidden')) {
    closePrivacyPolicy();
  }
});

if (privacyModal) {
  privacyModal.addEventListener('click', (e) => {
    if (e.target === privacyModal) closePrivacyPolicy();
  });
}

window.openPrivacyPolicy = openPrivacyPolicy;
