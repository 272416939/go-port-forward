// UI 逻辑：一秒一次轮询 /api/status，按状态驱动界面。
// token 从入口 URL 的查询参数取一次，随即从地址栏抹掉（避免留在历史记录里），
// 后续所有请求走 Authorization 头；服务端对 ?t= 的兼容保留给旧缓存页面。

const token = new URLSearchParams(location.search).get('t') || '';
if (token) {
  try { history.replaceState(null, '', location.pathname) } catch (e) {}
}

const el = (id) => document.getElementById(id);
const ui = {
  pill: el('statePill'), stateText: el('stateText'),
  elevateWarn: el('elevateWarn'), errBox: el('errBox'),
  code: el('code'), addr: el('addr'), codeId: el('codeId'), secret: el('secret'),
  manualBox: el('manualBox'),
  connect: el('btnConnect'), disconnect: el('btnDisconnect'),
  quit: el('btnQuit'),
  identity: el('identity'), device: el('device'), tunIP: el('tunIP'), uptime: el('uptime'),
  bytesUp: el('bytesUp'), bytesDown: el('bytesDown'),
  rateUp: el('rateUp'), rateDown: el('rateDown'), pktLine: el('pktLine'),
  routeRows: el('routeRows'), routeCount: el('routeCount'), logs: el('logs'),
  linkBadge: el('linkBadge'),
  linkLoss: el('linkLoss'), linkLossHint: el('linkLossHint'),
  linkReorder: el('linkReorder'), linkJitter: el('linkJitter'), linkRTT: el('linkRTT'),
  linkFEC: el('linkFEC'), linkFECHint: el('linkFECHint'),
  linkDrops: el('linkDrops'), linkDropsHint: el('linkDropsHint'),
};

const STATE_TEXT = {
  idle: '未连接', connecting: '正在连接…', connected: '已连接', error: '连接失败',
};

// dirty 为真时不要用服务端返回的值覆盖用户正在输入的内容。
const dirty = { addr: false, codeId: false };
let busy = false;
// stopped 在用户主动退出后置位：此后不再轮询，避免把"进程已退出"报成故障。
let stopped = false;

ui.addr.addEventListener('input', () => { dirty.addr = true; });
ui.codeId.addEventListener('input', () => { dirty.codeId = true; });
// 粘贴接入码时手工填的三项就没意义了，自动折起来避免冲突。
ui.code.addEventListener('input', () => {
  if (ui.code.value.trim()) ui.manualBox.open = false;
});

async function api(path, options) {
  options = Object.assign({}, options);
  options.headers = Object.assign({}, options.headers, { 'Authorization': 'Bearer ' + token });
  const res = await fetch(path, options);
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

// fmtPPM 把百万分之转成百分比字符串（后端用整数传，避免浮点在 JSON 里抖动）。
function fmtPPM(ppm) {
  if (!ppm) return '0%';
  const pct = ppm / 10000;
  return (pct < 0.01 ? '<0.01' : pct.toFixed(2)) + '%';
}

function fmtMS(ms) {
  if (!ms) return '—';
  return (ms < 1 ? ms.toFixed(2) : ms.toFixed(1)) + ' ms';
}

// 丢包率的档位：1% 是游戏体感的分界（60pps 下 1% ≈ 每秒卡 0.6 次）。
function lossLevel(ppm) {
  if (ppm >= 30000) return { cls: 'bad', text: '严重' };
  if (ppm >= 10000) return { cls: 'warn', text: '偏高' };
  if (ppm > 0) return { cls: 'ok', text: '轻微' };
  return { cls: 'ok', text: '无' };
}

function renderLink(s) {
  const link = s.link || {};
  const connected = s.state === 'connected';
  if (!connected) {
    ui.linkBadge.textContent = '—';
    ui.linkBadge.dataset.level = '';
    for (const k of ['linkLoss', 'linkReorder', 'linkJitter', 'linkRTT', 'linkFEC', 'linkDrops']) {
      ui[k].textContent = '—';
    }
    for (const k of ['linkLossHint', 'linkFECHint', 'linkDropsHint']) ui[k].textContent = '';
    return;
  }
  const lvl = lossLevel(link.loss_ppm || 0);
  ui.linkBadge.textContent = lvl.text;
  ui.linkBadge.dataset.level = lvl.cls;
  ui.linkLoss.textContent = fmtPPM(link.loss_ppm || 0);
  // 丢包偏高时才提示纠错——没开的时候说「可以开」，开了的时候不啰嗦。
  ui.linkLossHint.textContent = (link.loss_ppm || 0) >= 10000 && !link.fec_enabled
    ? '可让管理员开启前向纠错' : '';
  ui.linkReorder.textContent = fmtPPM(link.reorder_ppm || 0);
  ui.linkJitter.textContent = fmtMS(link.jitter_ms || 0);
  ui.linkRTT.textContent = fmtMS(link.rtt_ms || 0);

  if (link.fec_enabled) {
    ui.linkFEC.textContent = (link.fec_recovered || 0).toLocaleString() + ' 个';
    ui.linkFECHint.textContent = '已启用' + (link.dup_enabled ? '（含小包冗余）' : '');
  } else {
    ui.linkFEC.textContent = '未启用';
    ui.linkFECHint.textContent = link.dup_enabled ? '仅小包冗余' : '';
  }

  const drops = (link.pending_drops || 0) + (link.tun_dropped || 0) + Number(link.tx_dropped || 0);
  ui.linkDrops.textContent = drops ? drops.toLocaleString() + ' 个' : '0';
  ui.linkDropsHint.textContent = drops ? '进服瞬间可能卡顿' : '';
}

function renderRoutes(routes, rates) {
  const list = routes || [];
  ui.routeCount.textContent = list.length;
  if (list.length === 0) {
    ui.routeRows.innerHTML = '<tr class="empty"><td colspan="5">暂无活跃玩家</td></tr>';
    return;
  }
  ui.routeRows.replaceChildren(...list.map((r) => {
    const tr = document.createElement('tr');
    const cells = [
      { text: r.ip, cls: 'ip' },
      { text: fmtBytes(r.bytes_up), cls: 'num' },
      { text: fmtBytes(r.bytes_down), cls: 'num' },
      { text: fmtRate(rates.perIP.get(r.ip) || 0), cls: 'num muted' },
      { text: r.drops ? String(r.drops) : '—', cls: r.drops ? 'num bad' : 'num muted' },
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

  if (!dirty.addr && s.addr) ui.addr.value = s.addr;
  if (!dirty.codeId && s.code_id) ui.codeId.value = s.code_id;
  // 已保存过凭据时，密钥框留空即表示「沿用已保存的」，不回显密钥本身。
  if (s.has_cred && !ui.secret.value) ui.secret.placeholder = '已保存（留空即沿用）';

  const running = s.state === 'connected' || s.state === 'connecting';
  ui.connect.hidden = running;
  ui.disconnect.hidden = !running;
  for (const input of [ui.code, ui.addr, ui.codeId, ui.secret]) input.disabled = running;
  ui.connect.disabled = busy || !s.elevated;
  ui.disconnect.disabled = busy;

  ui.identity.textContent = s.code_id ? s.code_id : '—';
  ui.device.textContent = s.device || '—';
  ui.tunIP.textContent = s.state === 'connected' && s.tun_ip
    ? `${s.tun_ip}（网关 ${s.gateway || '—'}${s.mtu ? '，MTU ' + s.mtu : ''}）` : '—';
  ui.uptime.textContent = formatUptime(s.uptime_sec);

  const rates = computeRates(s);
  ui.bytesUp.textContent = fmtBytes(s.bytes_up);
  ui.bytesDown.textContent = fmtBytes(s.bytes_down);
  ui.rateUp.textContent = '↑ ' + fmtRate(rates.up);
  ui.rateDown.textContent = '↓ ' + fmtRate(rates.down);
  ui.pktLine.textContent = `数据包 ↑${(s.pkt_up || 0).toLocaleString()} / ↓${(s.pkt_down || 0).toLocaleString()}`;
  renderRoutes(s.routes, rates);
  renderLink(s);

  // 连接中不显示上一次的失败原因，避免误读为当前状态。
  showError(s.state === 'error' ? s.last_error : '');
  // 终态错误（换了设备、访问码被停用）不会自动重试，标签要说清楚，
  // 否则用户会以为再等一会儿就好了。
  if (s.state === 'error' && s.terminal) ui.stateText.textContent = '已停止（需处理）';

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
      body: JSON.stringify({
        code: ui.code.value.trim(),
        addr: ui.addr.value.trim(),
        code_id: ui.codeId.value.trim(),
        secret: ui.secret.value.trim(),
      }),
    });
    // 连接成功后清掉输入框里的凭据：它们已经落盘，界面上留着只是泄漏面。
    ui.code.value = '';
    ui.secret.value = '';
    dirty.addr = false;
    dirty.codeId = false;
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
