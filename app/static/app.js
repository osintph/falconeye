// ---- Tab navigation ----
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
    if (btn.dataset.tab === 'news') loadNews(currentNewsCategory);
  });
});

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
  } else if (ct.source === 'google_ct') {
    sourceBadge = '<span class="text-xs text-blue-400">via Google CT (crt.sh fallback)</span>';
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
