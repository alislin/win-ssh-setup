'use strict';

const http = require('http');
const net = require('net');
const dgram = require('dgram');
const os = require('os');
const { PAIR_HTTP_PORT, BEACON_UDP_PORT, MAGIC } = require('./config');

/** 网络错误分类，给出可操作的中文提示 */
function classifyError(e) {
  const code = e && e.code;
  if (code === 'ECONNREFUSED') return new Error('目标端口未监听：服务器端工具可能未运行');
  if (code === 'ETIMEDOUT') return new Error('连接超时：防火墙拦截或 IP 不可达');
  if (code === 'ECONNRESET') return new Error('连接被重置：网络或安全软件中断了连接');
  if (e instanceof Error) return e;
  return new Error(String(e));
}

/**
 * TCP 预检：快速判断目标端口是否可达（区分"服务未启动"与"被拦截"）。
 * @returns {Promise<true>} 失败时 reject（带分类后的错误信息）
 */
function preflightTcp({ host, port }, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port: port || PAIR_HTTP_PORT });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`无法在 ${Math.round(timeoutMs / 1000)} 秒内建立 TCP 连接（防火墙拦截或 IP 不可达，请核对服务器屏幕显示的地址）`));
    }, timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.once('error', (e) => {
      clearTimeout(timer);
      reject(classifyError(e));
    });
  });
}

/**
 * 监听 UDP 广播，收集局域网内正在等待配对的服务器。
 * @param {number} timeoutMs 监听时长
 * @returns {Promise<Array<{ip:string, hostname:string, httpPort:number}>>}
 */
function discover(timeoutMs = 5000) {
  return new Promise((resolve) => {
    const found = new Map();
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    sock.on('error', () => { /* 端口被占用等情况：静默，交给手动 IP 兜底 */ });
    sock.on('message', (msg, rinfo) => {
      try {
        const d = JSON.parse(msg.toString('utf8'));
        if (d && d.magic === MAGIC && d.httpPort && rinfo.address) {
          found.set(rinfo.address, { ip: rinfo.address, hostname: d.hostname, httpPort: d.httpPort });
        }
      } catch { /* 非本工具的广播包，忽略 */ }
    });
    try {
      sock.bind(BEACON_UDP_PORT);
    } catch { /* 绑定失败时 resolve 空，走手动输入 */ }
    setTimeout(() => {
      try { sock.close(); } catch { /* 忽略 */ }
      resolve([...found.values()]);
    }, timeoutMs);
  });
}

/**
 * 发送 POST 请求并流式消费 NDJSON 响应（step/audit 实时回调，done 汇总返回）。
 * 鉴权：配对请求传 code（X-Pair-Code），后续请求传 sessionToken（X-Session-Token）。
 * 分级超时：响应头 30s / 数据流空闲 30s / 总时长 timeoutMs（默认 180s）。
 * @returns {Promise<{type:'done', ...}>}
 */
function postNdjson({ host, port, urlPath, code, sessionToken, body, onStep, onConnected, timeoutMs = 180 * 1000, headerTimeoutMs = 30 * 1000, idleTimeoutMs = 30 * 1000 }) {
  return new Promise((resolve, reject) => {
    let done = null;
    let gotResponse = false;
    let finished = false;
    let watchdog = null;
    let totalTimer = null;
    let req = null;

    const clearTimers = () => {
      if (watchdog) { clearTimeout(watchdog); watchdog = null; }
      if (totalTimer) { clearTimeout(totalTimer); totalTimer = null; }
    };
    const fail = (err) => {
      if (finished) return;
      finished = true;
      clearTimers();
      try { if (req) req.destroy(); } catch { /* 忽略 */ }
      reject(err);
    };
    const finish = (obj) => {
      if (finished) return;
      finished = true;
      clearTimers();
      resolve(obj);
    };
    // 空闲看门狗：等待响应头阶段 30s；进入数据流阶段后每条数据重置
    const armWatchdog = () => {
      if (watchdog) clearTimeout(watchdog);
      watchdog = setTimeout(() => {
        req.destroy(new Error(gotResponse
          ? `服务器执行中断（${Math.round(idleTimeoutMs / 1000)} 秒无数据流），详情请查看服务器端窗口日志`
          : `已连接但 ${Math.round(headerTimeoutMs / 1000)} 秒未收到服务器响应（VPN/安全软件可能拦截响应流）`));
      }, gotResponse ? idleTimeoutMs : headerTimeoutMs);
    };

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    };
    if (code) headers['X-Pair-Code'] = code;
    if (sessionToken) headers['X-Session-Token'] = sessionToken;

    req = http.request({
      host,
      port: port || PAIR_HTTP_PORT,
      path: urlPath,
      method: 'POST',
      headers,
    }, (res) => {
      gotResponse = true;
      armWatchdog();
      if (onConnected) {
        try { onConnected(res.statusCode); } catch { /* 忽略 */ }
      }
      if (res.statusCode !== 200) {
        let buf = '';
        res.on('data', (ch) => { buf += ch; });
        res.on('end', () => {
          let msg = buf.trim();
          try { msg = JSON.parse(buf).error || msg; } catch { /* 保留原文 */ }
          fail(new Error(`服务器返回 ${res.statusCode}：${msg}`));
        });
        res.on('error', () => {});
        return;
      }
      let buf = '';
      res.setEncoding('utf8');
      const handleLine = (line) => {
        if (!line) return;
        let obj;
        try { obj = JSON.parse(line); } catch { return; }
        if (obj.type === 'done') done = obj;
        else if ((obj.type === 'step' || obj.type === 'audit') && onStep) onStep(obj);
      };
      res.on('data', (ch) => {
        armWatchdog();
        buf += ch;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          handleLine(buf.slice(0, i).trim());
          buf = buf.slice(i + 1);
        }
      });
      res.on('end', () => {
        handleLine(buf.trim());
        if (done) finish(done);
        else fail(new Error('连接中断，未收到完整结果'));
      });
    });
    totalTimer = setTimeout(() => req.destroy(new Error(`总时长超时（${Math.round(timeoutMs / 1000)} 秒）`)), timeoutMs);
    req.on('error', (e) => fail(classifyError(e)));
    armWatchdog();
    req.write(body);
    req.end();
  });
}

/** 配对：发送公钥，实时接收部署步骤与体检结果 */
function submit({ host, port, code, pubKey, onStep, onConnected }) {
  return postNdjson({
    host,
    port,
    urlPath: '/pair',
    code,
    body: JSON.stringify({ pubkey: pubKey, clientHostname: os.hostname() }),
    onStep,
    onConnected,
  });
}

/** 清理服务器上的旧公钥（按指纹，凭配对成功后签发的会话令牌鉴权） */
function cleanup({ host, port, sessionToken, fingerprints, keepFingerprint, onStep }) {
  return postNdjson({
    host,
    port,
    urlPath: '/pair/cleanup',
    sessionToken,
    body: JSON.stringify({ fingerprints, keepFingerprint }),
    onStep,
    timeoutMs: 60 * 1000,
  });
}

module.exports = { discover, submit, cleanup, preflightTcp };
