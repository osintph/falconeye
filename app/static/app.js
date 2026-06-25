// ---- Hash-based tab routing ----
// Tab name <-> URL hash <-> visible tab content
// Browser back/forward buttons walk through the hash history natively.

const VALID_TABS = ['home', 'crypto', 'scanner', 'domain', 'telegram', 'ip', 'sandbox', 'email', 'news'];
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
        <p class="text-sm text-white">${rdap.registrar.name || rdap.registrar.handle || 'Unknown'}</p>
        ${rdap.registrar.email ? `<p class="text-xs text-gray-400">${rdap.registrar.email}</p>` : ''}
      </div>` : ''}

      ${rdap.registrant ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Registrant</p>
        <p class="text-sm text-white">${rdap.registrant.name || rdap.registrant.handle || 'Redacted (GDPR)'}</p>
        ${rdap.registrant.email ? `<p class="text-xs text-gray-400">${rdap.registrant.email}</p>` : ''}
      </div>` : ''}

      ${rdap.abuse_contact ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Abuse Contact</p>
        <p class="text-sm text-white">${rdap.abuse_contact.email || rdap.abuse_contact.name || 'Not listed'}</p>
      </div>` : ''}

      ${rdap.nameservers && rdap.nameservers.length ? `
      <div class="mb-3">
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">Nameservers</p>
        <div class="flex flex-wrap gap-2">
          ${rdap.nameservers.map(ns => `<span class="text-xs bg-gray-800 px-2 py-1 rounded text-gray-300">${ns}</span>`).join('')}
        </div>
      </div>` : ''}

      ${rdap.status && rdap.status.length ? `
      <div>
        <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">EPP Status</p>
        <div class="flex flex-wrap gap-2">
          ${rdap.status.map(s => `<span class="text-xs bg-gray-800 px-2 py-1 rounded text-amber-300">${s}</span>`).join('')}
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

    el.innerHTML = data.map(item => `
      <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="news-card block">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-amber-400 font-bold">${item.feed_source}</span>
          <span class="text-xs text-gray-600">${fmtPHT(item.published_at)}</span>
        </div>
        <p class="text-sm text-white leading-snug mb-1">${item.title}</p>
        ${item.summary ? `<p class="text-xs text-gray-500 leading-relaxed line-clamp-2">${item.summary.replace(/<[^>]*>/g, '')}</p>` : ''}
      </a>`).join('');
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
  const photoHtml = data.photo_url
    ? `<img src="${data.photo_url}" class="w-16 h-16 rounded-full border border-gray-700" alt="" onerror="this.style.display='none'" />`
    : `<div class="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center text-amber-400 font-bold text-2xl">${(data.title || '?').charAt(0).toUpperCase()}</div>`;

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
            <h3 class="text-base font-bold text-white">${data.title}</h3>
            <p class="text-xs text-amber-400 mb-2">${data.username}</p>
            ${data.description ? `<p class="text-xs text-gray-400 max-w-2xl">${data.description}</p>` : ''}
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
                ${m.forwarded_from ? `<span class="text-xs text-blue-400">⤴ ${m.forwarded_from}</span>` : ''}
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
                <span class="text-xs bg-gray-800 text-amber-300 px-1.5 py-0.5 rounded">${item.brand}</span>
                <span class="text-xs ${item.url_status === 'online' ? 'text-green-400' : 'text-gray-500'} font-bold">${(item.url_status || 'unknown').toUpperCase()}</span>
                <span class="text-xs text-gray-600">${item.dateadded ? item.dateadded.split(' ')[0] : ''}</span>
              </div>
              <p class="text-xs text-gray-300 font-mono truncate">${item.url}</p>
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

    el.innerHTML = data.slice(0, 3).map(item => `
      <a href="${item.url}" target="_blank" rel="noopener noreferrer"
         class="bg-gray-900 border border-gray-800 hover:border-amber-400 rounded p-3 block transition">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-amber-400 font-bold">${item.feed_source}</span>
          <span class="text-xs text-gray-600">${fmtPHT(item.published_at)}</span>
        </div>
        <p class="text-sm text-white leading-snug line-clamp-3">${item.title}</p>
      </a>
    `).join('');
  } catch (e) {
    el.innerHTML = `<p class="text-xs text-red-400 col-span-3">Failed to load news: ${e.message}</p>`;
  }
}

// ---- Email Header Analyzer ----

document.getElementById('email-header-clear')?.addEventListener('click', () => {
  document.getElementById('email-header-input').value = '';
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
    const res = await fetch('/api/email-header/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({raw_header: raw}),
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

  let html = `
    <div class="bg-gray-900 border border-${verdictColor}-500 rounded p-5 mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-${verdictColor}-400 uppercase tracking-wider">BEC Assessment</h3>
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


// Load both on page ready (they fire in parallel)
loadThreatPulse();
loadLandingNews();
