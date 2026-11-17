'use strict';

const http = require('http');
const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const { PAIR_HTTP_PORT, BEACON_UDP_PORT, MAGIC, TEMP_FW_RULE, PAIR_CODE_ROTATE_MS } = require('./config');
const { run } = require('./exec');
const log = require('./log');
const { validatePubKey, fingerprint, authFilePaths, removeByFingerprints } = require('./keymgr');
const { runDeploy } = require('./deploy');
const { runAudit } = require('./audit');
const { lanIPs, userInfo, isAdminGroup } = require('./env');

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

/** 服务器端配对服务：HTTP 配对 + UDP 广播信标 + 临时防火墙规则 */
class PairServer {
  constructor({ rotateMs } = {}) {
    this.code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    this.session = null;
    this.rotateMs = rotateMs || PAIR_CODE_ROTATE_MS;
    this.rotateTimer = null;
    this.httpServer = null;
    this.beaconSocket = null;
    this.beaconTimer = null;
    this.fwAdded = false;
    this.stopped = false;
    this.busy = false;
  }

  /** 展示用配对码（3 位一组便于朗读） */
  displayCode() {
    return `${this.code.slice(0, 3)} ${this.code.slice(3)}`;
  }

  start() {
    this.startHttp();
    this.startBeacon();
    this.addFirewall();
    this.rotateTimer = setInterval(() => this.rotateTimed(), this.rotateMs);
  }

  startHttp() {
    const server = http.createServer((req, res) => this.handle(req, res));
    server.on('error', (e) => {
      if (e.code === 'EADDRINUSE') {
        log.error(`端口 ${PAIR_HTTP_PORT} 被占用，请关闭占用该端口的程序后重试`);
      } else {
        log.error(`配对服务异常：${e.message}`);
      }
      process.exit(1);
    });
    server.listen(PAIR_HTTP_PORT, '0.0.0.0', () => {
      log.info(`配对服务已启动，监听 TCP ${PAIR_HTTP_PORT}`);
    });
    this.httpServer = server;
  }

  handle(req, res) {
    const url = (req.url || '').split('?')[0];
    if (url === '/pair/cleanup' && req.method === 'POST') {
      this.handleCleanup(req, res);
      return;
    }
    if (req.method !== 'POST' || url !== '/pair') {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    this.handlePair(req, res);
  }

  readBody(req, res, onEnd) {
    let body = '';
    req.on('data', (ch) => {
      body += ch;
      if (body.length > 64 * 1024) req.destroy();
    });
    req.on('end', () => onEnd(body));
  }

  checkCode(req, res) {
    const code = String(req.headers['x-pair-code'] || '').trim();
    if (code === this.code) return true;
    log.warn(`配对码校验失败（来自 ${req.socket.remoteAddress}）`);
    this.failJson(res, 403, '配对码不正确');
    return false;
  }

  /** 生成新配对码并重显在屏幕（reason: 'used' 使用后轮换 / 'timer' 定时轮换） */
  newCode(reason) {
    this.code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    log.plain('');
    const codeText = `${log.c.green}${log.c.bold}${this.displayCode()}${log.c.reset}`;
    if (reason === 'timer') {
      const mins = Math.round(this.rotateMs / 60000);
      const period = mins >= 1 ? `每 ${mins} 分钟` : `每 ${Math.round(this.rotateMs / 1000)} 秒`;
      log.info(`配对码定时更新：${codeText} ← ${period}自动轮换，旧码作废；下一位客户端请使用新码`);
    } else {
      log.info(`配对码已更新：${codeText} ← 一次性使用，旧码已作废；下一位客户端请使用新码`);
    }
  }

  /** 配对码校验通过即消耗：换码 + 签发后续清理请求所用的会话令牌 */
  consumeCode() {
    this.newCode('used');
    this.session = {
      token: crypto.randomBytes(24).toString('hex'),
      expires: Date.now() + 10 * 60 * 1000,
    };
    return this.session.token;
  }

  /** 定时轮换：仅换码，不影响已签发的会话令牌 */
  rotateTimed() {
    this.newCode('timer');
  }

  /** 清理等后续请求的会话令牌校验（10 分钟有效，仅最新一次配对持有） */
  checkSession(req, res) {
    const token = String(req.headers['x-session-token'] || '').trim();
    const valid = this.session && token === this.session.token && Date.now() < this.session.expires;
    if (!valid) {
      log.warn(`会话令牌无效或已过期（来自 ${req.socket.remoteAddress}）`);
      this.failJson(res, 403, '会话令牌无效或已过期，请重新配对');
    }
    return valid;
  }

  failJson(res, code, msg) {
    try {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ type: 'done', ok: false, error: msg }));
    } catch { /* 连接可能已断开 */ }
  }

  handlePair(req, res) {
    this.readBody(req, res, (body) => {
      let payload;
      try {
        payload = JSON.parse(body);
      } catch {
        return this.failJson(res, 400, '请求体不是合法 JSON');
      }
      if (!this.checkCode(req, res)) return;
      if (this.busy) return this.failJson(res, 409, '服务器正在处理另一个配对请求，请稍后重试');
      // 配对码一次性使用：校验通过即轮换并签发会话令牌（后续清理请求凭令牌鉴权）
      const sessionToken = this.consumeCode();
      if (!validatePubKey(payload.pubkey || '')) {
        return this.failJson(res, 400, '公钥格式不正确（本次配对码已消耗，请使用服务器屏幕上的新配对码重试）');
      }

      const clientHost = String(payload.clientHostname || 'unknown');
      log.info(`客户端 ${clientHost}（${req.socket.remoteAddress}）配对成功，开始部署...`);
      this.busy = true;
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8' });

      const writeLine = (obj) => {
        try { res.write(`${JSON.stringify(obj)}\n`); } catch { /* 忽略 */ }
      };
      const emitStep = (s) => {
        log.step(s);
        writeLine({ type: 'step', name: s.name, status: s.status, detail: s.detail });
      };

      (async () => {
        const r = await runDeploy({
          pubKey: payload.pubkey.trim(),
          clientHostname: payload.clientHostname || '',
          onStep: emitStep,
        });

        // 部署成功后立即执行配置体检（无连接，纯配置层检查），结果实时回传客户端
        let audit = null;
        if (r.ok) {
          log.info('部署完成，开始配置体检...');
          audit = await runAudit({
            pubKeys: [payload.pubkey.trim()],
            onStep: (s) => {
              log.step(s);
              writeLine({ type: 'audit', name: s.name, status: s.status, detail: s.detail, fixId: s.fixId || undefined });
            },
          });
          log[audit.ok ? 'ok' : 'warn'](
            `配置体检结论：${audit.failures} 项失败，${audit.warnings} 项警告${audit.ok ? ' —— 按当前配置，免密登录应可生效' : ''}`,
          );
        }

        const { user } = userInfo();
        writeLine({
          type: 'done',
          ok: r.ok,
          serverUser: user,
          serverHostname: os.hostname(),
          paths: {
            userKeys: r.userKeysPath,
            adminKeys: r.adminKeysPath,
            configBackup: r.configBackup,
          },
          staleKeys: (r.staleKeys || []).map((s) => ({ fingerprint: s.fingerprint, algo: s.algo, comment: s.comment })),
          audit: audit ? { ok: audit.ok, failures: audit.failures, warnings: audit.warnings } : null,
          sessionToken,
        });
        res.end();
        if (r.ok) log.ok(`部署与体检完成，已通知客户端 ${clientHost}。可继续等待其他客户端，Ctrl+C 退出`);
        else log.error('部署存在失败步骤，详情见上方日志');
      })()
        .catch((e) => {
          writeLine({ type: 'done', ok: false, error: e.message });
          res.end();
          log.error(`部署异常：${e.message}`);
        })
        .finally(() => {
          this.busy = false;
        });
    });
  }

  /** 按指纹清理旧公钥（更换 key 场景），永不删除 keepFingerprint */
  handleCleanup(req, res) {
    this.readBody(req, res, (body) => {
      let payload;
      try {
        payload = JSON.parse(body);
      } catch {
        return this.failJson(res, 400, '请求体不是合法 JSON');
      }
      if (!this.checkSession(req, res)) return;
      if (this.busy) return this.failJson(res, 409, '服务器正在处理另一个请求，请稍后重试');
      const fps = Array.isArray(payload.fingerprints) ? payload.fingerprints : [];
      if (!fps.length) return this.failJson(res, 400, 'fingerprints 不能为空');
      if (fps.some((f) => !FP_RE.test(String(f)))) return this.failJson(res, 400, '指纹格式不正确');

      const files = [authFilePaths().user];
      if (isAdminGroup() && fs.existsSync(authFilePaths().admin)) files.push(authFilePaths().admin);

      log.info(`客户端请求清理 ${fps.length} 个旧公钥指纹...`);
      this.busy = true;
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8' });
      const writeLine = (obj) => {
        try { res.write(`${JSON.stringify(obj)}\n`); } catch { /* 忽略 */ }
      };
      const emitStep = (s) => {
        log.step(s);
        writeLine({ type: 'step', name: s.name, status: s.status, detail: s.detail });
      };

      try {
        const result = removeByFingerprints({
          fingerprints: fps,
          keepFingerprint: String(payload.keepFingerprint || ''),
          files,
        });
        emitStep({
          name: '清理 备份授权文件',
          status: result.backups.length ? 'OK' : 'SKIP',
          detail: result.backups.length ? result.backups.join(' ; ') : '无需修改',
        });
        emitStep({
          name: '清理 删除旧公钥',
          status: result.removed.length ? 'OK' : 'SKIP',
          detail: result.removed.length
            ? `已删除 ${result.removed.length} 个：${result.removed.map((r) => r.fingerprint).join(', ')}`
            : '未找到匹配的旧公钥',
        });
        writeLine({ type: 'done', ok: true, removed: result.removed.length, backups: result.backups });
        res.end();
        log.ok(`旧公钥清理完成（删除 ${result.removed.length} 个）。authorized_keys 即时生效，无需重启服务`);
      } catch (e) {
        writeLine({ type: 'done', ok: false, error: e.message });
        res.end();
        log.error(`清理异常：${e.message}`);
      } finally {
        this.busy = false;
      }
    });
  }

  startBeacon() {
    const sock = dgram.createSocket('udp4');
    sock.on('error', () => {});
    sock.bind(() => {
      sock.setBroadcast(true);
      const send = () => {
        if (this.stopped) return;
        const msg = Buffer.from(JSON.stringify({ magic: MAGIC, hostname: os.hostname(), httpPort: PAIR_HTTP_PORT }));
        sock.send(msg, BEACON_UDP_PORT, '255.255.255.255', () => {});
      };
      send();
      this.beaconTimer = setInterval(send, 2000);
    });
    this.beaconSocket = sock;
  }

  addFirewall() {
    run('netsh.exe', ['advfirewall', 'firewall', 'delete', 'rule', `name=${TEMP_FW_RULE}`]);
    const r = run('netsh.exe', [
      'advfirewall', 'firewall', 'add', 'rule', `name=${TEMP_FW_RULE}`,
      'dir=in', 'action=allow', 'protocol=TCP', `localPort=${PAIR_HTTP_PORT}`, 'profile=any',
    ]);
    if (r.code === 0) {
      this.fwAdded = true;
      log.ok(`已添加临时防火墙规则（TCP ${PAIR_HTTP_PORT}），退出时自动删除`);
    } else {
      log.warn('添加临时防火墙规则失败，若客户端连不上请检查防火墙设置');
    }
  }

  stop() {
    if (this.stopped) return;
    this.stopped = true;
    if (this.rotateTimer) clearInterval(this.rotateTimer);
    if (this.beaconTimer) clearInterval(this.beaconTimer);
    try { if (this.beaconSocket) this.beaconSocket.close(); } catch { /* 忽略 */ }
    try { if (this.httpServer) this.httpServer.close(); } catch { /* 忽略 */ }
    if (this.fwAdded) {
      run('netsh.exe', ['advfirewall', 'firewall', 'delete', 'rule', `name=${TEMP_FW_RULE}`]);
      log.info('已删除临时防火墙规则');
    }
  }
}

module.exports = { PairServer };
