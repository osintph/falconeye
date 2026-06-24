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
          <p class="text-xs text-gray-500 uppercase tracking-wide mb-1">First Seen</p>
          <p class="text-gray-300 text-xs">${data.first_seen}</p>
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

    const timeStr = tx.time
      ? (typeof tx.time === 'number'
          ? new Date(tx.time).toISOString().replace('T', ' ').slice(0, 19)
          : String(tx.time).slice(0, 19))
      : '';

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
          <span class="text-xs text-gray-600">${item.published_at ? item.published_at.slice(0, 16) : ''}</span>
        </div>
        <p class="text-sm text-white leading-snug mb-1">${item.title}</p>
        ${item.summary ? `<p class="text-xs text-gray-500 leading-relaxed line-clamp-2">${item.summary.replace(/<[^>]*>/g, '')}</p>` : ''}
      </a>`).join('');
  } catch (e) {
    el.innerHTML = `<p class="text-red-400 text-sm">Load failed: ${e.message}</p>`;
  }
}
