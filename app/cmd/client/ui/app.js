// UI 逻辑：一秒一次轮询 /api/status，按状态驱动界面。
// token 从入口 URL 的查询参数取，后续所有请求都带上。

const token = new URLSearchParams(location.search).get('t') || '';

const el = (id) => document.getElementById(id);
const ui = {
  pill: el('statePill'), stateText: el('stateText'),
  elevateWarn: el('elevateWarn'), errBox: el('errBox'),
  addr: el('addr'), connect: el('btnConnect'), disconnect: el('btnDisconnect'),
  quit: el('btnQuit'),
  tunIP: el('tunIP'), uptime: el('uptime'),
  bytesUp: el('bytesUp'), bytesDown: el('bytesDown'),
  rateUp: el('rateUp'), rateDown: el('rateDown'), pktLine: el('pktLine'),
  routeRows: el('routeRows'), routeCount: el('routeCount'), logs: el('logs'),
};

const STATE_TEXT = {
  idle: '未连接', connecting: '正在连接…', connected: '已连接', error: '连接失败',
};

// addrDirty 为真时不要用服务端返回的地址覆盖用户正在输入的内容。
let addrDirty = false;
let busy = false;
// stopped 在用户主动退出后置位：此后不再轮询，避免把"进程已退出"报成故障。
let stopped = false;

ui.addr.addEventListener('input', () => { addrDirty = true; });

async function api(path, options) {
  const sep = path.includes('?') ? '&' : '?';
  const res = await fetch(`${path}${sep}t=${encodeURIComponent(token)}`, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `请求失败（${res.status}）`);
  return body;
}

function showError(msg) {
  ui.errBox.textContent = msg;
  ui.errBox.hidden = !msg;
}

// fmtBytes 与主项目 Web 面板保持一致：1024 进制、KB/MB 标签、一位小数。
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(1) + ' ' + u[i];
}

function fmtRate(bytesPerSec) {
  return fmtBytes(Math.max(0, Math.round(bytesPerSec))) + '/s';
}

function formatUptime(sec) {
  if (!sec) return '—';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

// 速率靠前后两次轮询做差分算出，后端不存历史。
// prev 记录上一次的字节数与时间戳；连接重置（字节数变小）时归零而不是显示负值。
let prev = null;

function computeRates(s) {
  const now = performance.now();
  const perIP = new Map();
  let up = 0, down = 0;

  if (prev) {
    const dt = (now - prev.at) / 1000;
    if (dt > 0.2) {
      const delta = (cur, old) => (cur >= old ? (cur - old) / dt : 0);
      up = delta(s.bytes_up, prev.up);
      down = delta(s.bytes_down, prev.down);
      for (const r of s.routes || []) {
        const o = prev.perIP.get(r.ip);
        if (o) perIP.set(r.ip, delta(r.bytes_up, o.up) + delta(r.bytes_down, o.down));
      }
    } else {
      // 间隔过短，沿用上一次的结果，避免除以极小数导致数字乱跳。
      return prev.rates;
    }
  }

  const rates = { up, down, perIP };
  prev = {
    at: now, up: s.bytes_up, down: s.bytes_down, rates,
    perIP: new Map((s.routes || []).map((r) => [r.ip, { up: r.bytes_up, down: r.bytes_down }])),
  };
  return rates;
}

function renderRoutes(routes, rates) {
  const list = routes || [];
  ui.routeCount.textContent = list.length;
  if (list.length === 0) {
    ui.routeRows.innerHTML = '<tr class="empty"><td colspan="4">暂无活跃玩家</td></tr>';
    return;
  }
  ui.routeRows.replaceChildren(...list.map((r) => {
    const tr = document.createElement('tr');
    const cells = [
      { text: r.ip, cls: 'ip' },
      { text: fmtBytes(r.bytes_up), cls: 'num' },
      { text: fmtBytes(r.bytes_down), cls: 'num' },
      { text: fmtRate(rates.perIP.get(r.ip) || 0), cls: 'num muted' },
    ];
    for (const c of cells) {
      const td = document.createElement('td');
      td.className = c.cls;
      td.textContent = c.text;
      tr.appendChild(td);
    }
    return tr;
  }));
}

function render(s) {
  ui.pill.dataset.state = s.state;
  ui.stateText.textContent = STATE_TEXT[s.state] || s.state;
  ui.elevateWarn.hidden = s.elevated;

  if (!addrDirty && s.addr) ui.addr.value = s.addr;

  const running = s.state === 'connected' || s.state === 'connecting';
  ui.connect.hidden = running;
  ui.disconnect.hidden = !running;
  ui.addr.disabled = running;
  ui.connect.disabled = busy || !s.elevated;
  ui.disconnect.disabled = busy;

  ui.tunIP.textContent = s.state === 'connected' ? s.tun_ip : '—';
  ui.uptime.textContent = formatUptime(s.uptime_sec);

  const rates = computeRates(s);
  ui.bytesUp.textContent = fmtBytes(s.bytes_up);
  ui.bytesDown.textContent = fmtBytes(s.bytes_down);
  ui.rateUp.textContent = '↑ ' + fmtRate(rates.up);
  ui.rateDown.textContent = '↓ ' + fmtRate(rates.down);
  ui.pktLine.textContent = `数据包 ↑${(s.pkt_up || 0).toLocaleString()} / ↓${(s.pkt_down || 0).toLocaleString()}`;
  renderRoutes(s.routes, rates);

  // 连接中不显示上一次的失败原因，避免误读为当前状态。
  showError(s.state === 'error' ? s.last_error : '');

  const logs = s.logs || [];
  if (logs.length) {
    const atBottom = ui.logs.scrollHeight - ui.logs.scrollTop - ui.logs.clientHeight < 24;
    ui.logs.textContent = logs.join('\n');
    if (atBottom) ui.logs.scrollTop = ui.logs.scrollHeight;
  }
}

async function poll() {
  try {
    render(await api('/api/status'));
  } catch (err) {
    ui.stateText.textContent = '后台已停止';
    ui.pill.dataset.state = 'error';
    showError(`无法连接到后台服务：${err.message}。请关闭窗口后重新启动程序。`);
  }
}

ui.connect.addEventListener('click', async () => {
  busy = true;
  showError('');
  try {
    await api('/api/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ addr: ui.addr.value.trim() }),
    });
    addrDirty = false;
  } catch (err) {
    showError(err.message);
  } finally {
    busy = false;
    poll();
  }
});

ui.disconnect.addEventListener('click', async () => {
  busy = true;
  try {
    await api('/api/disconnect', { method: 'POST' });
  } catch (err) {
    showError(err.message);
  } finally {
    busy = false;
    poll();
  }
});

ui.quit.addEventListener('click', async () => {
  if (!confirm('退出程序将断开隧道并清理路由，确定吗？')) return;
  stopped = true;
  ui.pill.dataset.state = 'idle';
  ui.stateText.textContent = '正在退出…';
  try {
    await api('/api/quit', { method: 'POST' });
  } catch (_) {
    // 进程可能在响应写回前就退出了，这不是错误。
  }
});

poll();
setInterval(() => { if (!stopped) poll(); }, 1000);
