'use strict';

const http = require('http');
const dgram = require('dgram');
const os = require('os');
const { PAIR_HTTP_PORT, BEACON_UDP_PORT, MAGIC } = require('./config');

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
 * @returns {Promise<{type:'done', ...}>}
 */
function postNdjson({ host, port, urlPath, code, sessionToken, body, onStep, timeoutMs = 180 * 1000 }) {
  return new Promise((resolve, reject) => {
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    };
    if (code) headers['X-Pair-Code'] = code;
    if (sessionToken) headers['X-Session-Token'] = sessionToken;
    const req = http.request({
      host,
      port: port || PAIR_HTTP_PORT,
      path: urlPath,
      method: 'POST',
      headers,
    }, (res) => {
      if (res.statusCode !== 200) {
        let buf = '';
        res.on('data', (ch) => { buf += ch; });
        res.on('end', () => {
          let msg = buf.trim();
          try { msg = JSON.parse(buf).error || msg; } catch { /* 保留原文 */ }
          reject(new Error(`服务器返回 ${res.statusCode}：${msg}`));
        });
        return;
      }
      let buf = '';
      let done = null;
      res.setEncoding('utf8');
      const handleLine = (line) => {
        if (!line) return;
        let obj;
        try { obj = JSON.parse(line); } catch { return; }
        if (obj.type === 'done') done = obj;
        else if ((obj.type === 'step' || obj.type === 'audit') && onStep) onStep(obj);
      };
      res.on('data', (ch) => {
        buf += ch;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          handleLine(buf.slice(0, i).trim());
          buf = buf.slice(i + 1);
        }
      });
      res.on('end', () => {
        handleLine(buf.trim());
        if (done) resolve(done);
        else reject(new Error('连接中断，未收到完整结果'));
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('等待服务器响应超时')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/** 配对：发送公钥，实时接收部署步骤与体检结果 */
function submit({ host, port, code, pubKey, onStep }) {
  return postNdjson({
    host,
    port,
    urlPath: '/pair',
    code,
    body: JSON.stringify({ pubkey: pubKey, clientHostname: os.hostname() }),
    onStep,
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

module.exports = { discover, submit, cleanup };
