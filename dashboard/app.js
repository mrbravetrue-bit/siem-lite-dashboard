const GREEN = '#39ff88';
const AMBER = '#ffd166';
const ORANGE = '#ff9f4d';
const RED = '#ff4d5e';
const DIM = '#4d7a5c';
const SEV_COLOR = { CRITICAL: RED, HIGH: ORANGE, MEDIUM: AMBER, LOW: DIM };

Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.color = '#6f9c81';
Chart.defaults.borderColor = 'rgba(28,51,34,0.6)';

function typeHeaderCommand() {
  const el = document.getElementById('headerCmd');
  const text = 'tail -f /var/log/siem/alerts.log';
  let i = 0;
  const interval = setInterval(() => {
    el.textContent = text.slice(0, i + 1);
    i++;
    if (i === text.length) clearInterval(interval);
  }, 40);
}

function fmtHour(bucket) {
  // bucket like "2026-07-10T08" -> "08:00"
  return bucket.slice(11, 13) + ':00';
}

function renderStats(data) {
  document.getElementById('statEvents').textContent = data.totals.events.toLocaleString();
  document.getElementById('statAlerts').textContent = data.totals.alerts.toLocaleString();
  document.getElementById('statIps').textContent = data.totals.unique_ips.toLocaleString();

  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const top = order.find(s => (data.severity_counts[s] || 0) > 0) || '--';
  const el = document.getElementById('statSeverity');
  el.textContent = top;
  el.style.color = SEV_COLOR[top] || '#d5f5e0';
  document.getElementById('statSeveritySub').textContent =
    top === '--' ? 'no alerts yet' : `${data.severity_counts[top]} alert(s) at this level`;

  document.getElementById('generatedAt').textContent =
    data.generated_at ? `last event: ${data.generated_at.replace('T', ' ')}` : '';
}

function renderTimeline(data) {
  const ctx = document.getElementById('timelineChart');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.timeline.map(([bucket]) => fmtHour(bucket)),
      datasets: [{
        label: 'events/hr',
        data: data.timeline.map(([, count]) => count),
        borderColor: GREEN,
        backgroundColor: 'rgba(57,255,136,0.08)',
        fill: true,
        tension: 0.3,
        pointRadius: 0,
        borderWidth: 2,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(28,51,34,0.4)' } },
        y: { grid: { color: 'rgba(28,51,34,0.4)' }, beginAtZero: true },
      },
    },
  });
}

function renderSeverity(data) {
  const ctx = document.getElementById('severityChart');
  const labels = Object.keys(data.severity_counts);
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: labels.map(l => data.severity_counts[l]),
        backgroundColor: labels.map(l => SEV_COLOR[l] || DIM),
        borderColor: '#0b120d',
        borderWidth: 2,
      }],
    },
    options: {
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12, font: { size: 11 } } } },
    },
  });
}

function renderTypes(data) {
  const ctx = document.getElementById('typeChart');
  const labels = Object.keys(data.type_counts);
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: labels.map(l => data.type_counts[l]),
        backgroundColor: GREEN,
        borderRadius: 3,
        maxBarThickness: 36,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 10 } } },
        y: { grid: { color: 'rgba(28,51,34,0.4)' }, beginAtZero: true, ticks: { stepSize: 1 } },
      },
    },
  });
}

function renderIpTable(data) {
  const tbody = document.querySelector('#ipTable tbody');
  data.top_offending_ips.forEach(([ip, count]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="ip-badge">${ip}</td><td>${count}</td>`;
    tbody.appendChild(tr);
  });
}

function renderFeed(data) {
  const body = document.getElementById('feedBody');
  if (data.alerts.length === 0) {
    body.innerHTML = '<div class="feed-line dim">// no alerts detected in current window</div>';
    return;
  }
  data.alerts.forEach((a, idx) => {
    setTimeout(() => {
      const line = document.createElement('div');
      line.className = 'feed-line';
      line.innerHTML =
        `<span class="feed-ts">${a.timestamp.replace('T', ' ')}</span>` +
        `<span class="sev sev-${a.severity}">${a.severity}</span>` +
        `<span class="feed-ip">${a.ip}</span> ` +
        `<span>${a.type}: ${a.message}</span>`;
      body.appendChild(line);
      body.scrollTop = body.scrollHeight;
    }, idx * 180);
  });
}

async function init() {
  typeHeaderCommand();
  try {
    const res = await fetch('data.json');
    const data = await res.json();
    renderStats(data);
    renderTimeline(data);
    renderSeverity(data);
    renderTypes(data);
    renderIpTable(data);
    renderFeed(data);
  } catch (err) {
    document.getElementById('feedBody').innerHTML =
      `<div class="feed-line">// failed to load data.json — run the pipeline first (see README)</div>`;
    console.error(err);
  }
}

init();
