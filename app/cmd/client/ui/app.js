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
  pktIn: el('pktIn'), pktOut: el('pktOut'),
  routes: el('routes'), routeCount: el('routeCount'), logs: el('logs'),
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

function formatUptime(sec) {
  if (!sec) return '—';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

function renderRoutes(list) {
  const routes = list || [];
  ui.routeCount.textContent = routes.length;
  if (routes.length === 0) {
    ui.routes.innerHTML = '<li class="empty">暂无活跃玩家</li>';
    return;
  }
  ui.routes.replaceChildren(...routes.map((ip) => {
    const li = document.createElement('li');
    li.textContent = ip;
    return li;
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
  ui.pktIn.textContent = (s.pkt_in || 0).toLocaleString();
  ui.pktOut.textContent = (s.pkt_out || 0).toLocaleString();
  renderRoutes(s.routes);

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
    ui.stateText.textContent = '界面已断开';
    ui.pill.dataset.state = 'error';
    showError(`无法连接到本地服务：${err.message}。请重新启动程序。`);
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
  try {
    await api('/api/quit', { method: 'POST' });
  } catch (_) {
    // 进程可能在响应写回前就退出了，这不是错误。
  }
  document.body.classList.add('is-closed');
  ui.pill.dataset.state = 'idle';
  ui.stateText.textContent = '程序已退出';
  showError('程序已退出，可以关闭此页面。');
});

poll();
setInterval(() => { if (!stopped) poll(); }, 1000);
