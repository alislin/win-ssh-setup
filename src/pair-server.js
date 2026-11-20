'use strict';

const http = require('http');
const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const { PAIR_HTTP_PORT, BEACON_UDP_PORT, MAGIC, TEMP_FW_RULE, PAIR_CODE_ROTATE_MS, PAIR_PERSIST_CODE_DIGITS, PAIR_MAX_CODE_FAILS, PAIR_LOCKOUT_MS } = require('./config');
const { run, runPS } = require('./exec');
const log = require('./log');
const { validatePubKey, fingerprint, authFilePaths, removeByFingerprints } = require('./keymgr');
const { runDeploy } = require('./deploy');
const { runAudit } = require('./audit');
const { lanIPs, userInfo, isAdminGroup } = require('./env');

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

/** 服务器端配对服务：HTTP 配对 + UDP 广播信标 + 临时防火墙规则 + 持久配对码（异地连接） */
class PairServer {
  constructor({ rotateMs } = {}) {
    this.code = this.genCode(6);
    this.persistent = false;                // 持久码模式：不轮换、可重复使用，直至手动销毁或进程退出
    this.session = null;                    // 会话令牌槽，仅最新一次配对持有
    this.rotateMs = rotateMs || PAIR_CODE_ROTATE_MS;
    this.rotateTimer = null;
    this.fails = 0;                         // 配对码连续校验失败计数（防爆破锁定）
    this.lockedUntil = 0;                   // 锁定截止时间戳（毫秒），0 表示未锁定
    this.httpServer = null;
    this.beaconSocket = null;
    this.beaconTimer = null;
    this.fwAdded = false;
    this.fwMergePrev = null;                // 组策略管控场景：临时开启本地规则合并的配置文件列表（退出时还原）
    this.stopped = false;
    this.busy = false;
  }

  /** 生成指定位数的纯数字配对码 */
  genCode(digits) {
    return String(crypto.randomInt(0, 10 ** digits)).padStart(digits, '0');
  }

  /** 展示用配对码（按位数对半分组便于朗读：6 位 → 123 456，8 位 → 1234 5678） */
  displayCode() {
    const half = Math.ceil(this.code.length / 2);
    return `${this.code.slice(0, half)} ${this.code.slice(half)}`;
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
    if (url === '/pair/destroy' && req.method === 'POST') {
      this.handleDestroy(req, res);
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
    // 防爆破锁定：连续错误达到阈值后，锁定期间一律拒绝
    if (Date.now() < this.lockedUntil) {
      const mins = Math.ceil((this.lockedUntil - Date.now()) / 60000);
      log.warn(`配对码锁定中，拒绝请求（剩余约 ${mins} 分钟，来自 ${req.socket.remoteAddress}）`);
      this.failJson(res, 429, `配对码连续错误次数过多，已锁定，请约 ${mins} 分钟后再试`);
      return false;
    }
    const code = String(req.headers['x-pair-code'] || '').trim();
    // timingSafeEqual 需等长 Buffer；长度不同直接判失败（同样计入失败次数）
    const ok = code.length === this.code.length
      && crypto.timingSafeEqual(Buffer.from(code), Buffer.from(this.code));
    if (ok) {
      this.fails = 0;
      return true;
    }
    this.fails += 1;
    if (this.fails >= PAIR_MAX_CODE_FAILS) {
      this.lockedUntil = Date.now() + PAIR_LOCKOUT_MS;
      this.fails = 0;
      log.error(`配对码连续错误 ${PAIR_MAX_CODE_FAILS} 次，已锁定 ${Math.round(PAIR_LOCKOUT_MS / 60000)} 分钟（来源 ${req.socket.remoteAddress}）——若非本人操作请检查网络暴露面`);
    } else {
      log.warn(`配对码校验失败（第 ${this.fails}/${PAIR_MAX_CODE_FAILS} 次，来自 ${req.socket.remoteAddress}）`);
    }
    this.failJson(res, 403, '配对码不正确');
    return false;
  }

  /** 生成新临时配对码并重显在屏幕（reason: 'used' 使用后轮换 / 'timer' 定时轮换 / 'persistent-off' 销毁持久码后） */
  newCode(reason) {
    this.code = this.genCode(6);
    log.plain('');
    const codeText = `${log.c.green}${log.c.bold}${this.displayCode()}${log.c.reset}`;
    if (reason === 'timer') {
      const mins = Math.round(this.rotateMs / 60000);
      const period = mins >= 1 ? `每 ${mins} 分钟` : `每 ${Math.round(this.rotateMs / 1000)} 秒`;
      log.info(`配对码定时更新：${codeText} ← ${period}自动轮换，旧码作废；下一位客户端请使用新码`);
    } else if (reason === 'persistent-off') {
      log.info(`持久配对码已销毁，已切换回临时码：${codeText} ← 每 ${Math.round(this.rotateMs / 60000)} 分钟自动轮换`);
    } else {
      log.info(`配对码已更新：${codeText} ← 一次性使用，旧码已作废；下一位客户端请使用新码`);
    }
  }

  /** 配对码校验通过后调用：持久码保持不变，临时码立即轮换；并签发后续清理/销毁请求所用的会话令牌 */
  consumeCode() {
    if (this.persistent) {
      log.info('持久配对码保持有效（不轮换，可继续用于后续客户端）');
    } else {
      this.newCode('used');
    }
    this.fails = 0;
    this.session = {
      token: crypto.randomBytes(24).toString('hex'),
      expires: Date.now() + 10 * 60 * 1000,
    };
    return this.session.token;
  }

  /** 手动激活持久配对码：8 位数字，不轮换、可重复使用，直至销毁或进程退出（已激活则仅重显，不换码） */
  createPersistentCode() {
    if (!this.persistent) {
      this.code = this.genCode(PAIR_PERSIST_CODE_DIGITS);
      this.persistent = true;
      if (this.rotateTimer) { clearInterval(this.rotateTimer); this.rotateTimer = null; }
      log.plain('');
      log.info(`持久配对码已激活：${log.c.green}${log.c.bold}${this.displayCode()}${log.c.reset}`);
      log.warn('该码在进程运行期间持续有效、可重复使用；异地连接需通过端口映射或 VPN 保证本机 22887 端口可达');
      log.warn('期间请保持本机开机联网（建议暂时关闭睡眠）并保持本窗口开启；按 [d] 销毁或退出进程即全部失效');
    } else {
      log.info(`当前持久配对码（未变化）：${log.c.green}${log.c.bold}${this.displayCode()}${log.c.reset}`);
    }
  }

  /** 销毁持久配对码，回到临时码模式（恢复定时轮换）。@returns {boolean} 是否确实销毁了持久码 */
  destroyPersistentCode() {
    if (!this.persistent) {
      log.info('当前没有激活的持久配对码');
      return false;
    }
    this.persistent = false;
    this.rotateTimer = setInterval(() => this.rotateTimed(), this.rotateMs);
    this.newCode('persistent-off');
    return true;
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

  okJson(res, obj) {
    try {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(obj));
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
      // 临时码一次性使用：校验通过即轮换；持久码保持不变；两种模式均签发会话令牌（后续清理/销毁请求凭令牌鉴权）
      const sessionToken = this.consumeCode();
      if (!validatePubKey(payload.pubkey || '')) {
        return this.failJson(res, 400, this.persistent
          ? '公钥格式不正确（持久配对码仍有效，修正后可直接重试）'
          : '公钥格式不正确（本次配对码已消耗，请使用服务器屏幕上的新配对码重试）');
      }

      const clientHost = String(payload.clientHostname || 'unknown');
      log.info(`客户端 ${clientHost}（${req.socket.remoteAddress}）配对成功，开始部署...`);
      this.busy = true;
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8' });
      // VPN/高延迟路径下小包流式传输：立即冲刷响应头并禁用 Nagle，避免首包被缓冲
      if (res.socket) res.socket.setNoDelay(true);
      res.flushHeaders();

      const writeLine = (obj) => {
        try { res.write(`${JSON.stringify(obj)}\n`); } catch { /* 忽略 */ }
      };
      const emitStep = (s) => {
        log.step(s);
        writeLine({ type: 'step', name: s.name, status: s.status, detail: s.detail });
      };
      // 受理即回执：客户端 1 秒内必有首条反馈，用于区分"未连上"与"执行中"
      emitStep({ name: '0/6 受理', status: 'OK', detail: `客户端 ${clientHost}（${req.socket.remoteAddress}）` });

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
          persistent: this.persistent,
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
      if (res.socket) res.socket.setNoDelay(true);
      res.flushHeaders();
      const writeLine = (obj) => {
        try { res.write(`${JSON.stringify(obj)}\n`); } catch { /* 忽略 */ }
      };
      const emitStep = (s) => {
        log.step(s);
        writeLine({ type: 'step', name: s.name, status: s.status, detail: s.detail });
      };
      emitStep({ name: '清理 受理', status: 'OK', detail: `${fps.length} 个指纹` });

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

  /** 远程销毁持久配对码（凭配对成功签发的会话令牌鉴权），销毁后服务器回到临时码模式 */
  handleDestroy(req, res) {
    this.readBody(req, res, () => {
      if (!this.checkSession(req, res)) return;
      const destroyed = this.destroyPersistentCode();
      this.okJson(res, { type: 'done', ok: true, destroyed, persistent: this.persistent });
      if (destroyed) log.ok('客户端已远程销毁持久配对码，服务器回到临时码模式');
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
      this.ensureRuleEffective();
      log.info(`客户端可先执行 Test-NetConnection 服务器IP -Port ${PAIR_HTTP_PORT} 验证配对端口可达`);
    } else {
      log.warn('添加临时防火墙规则失败，若客户端连不上请检查防火墙设置');
    }
  }

  /**
   * 确保放行规则真正生效。
   * 部分机器的防火墙策略由组策略管控（AllowLocalFirewallRules=False），本地添加的规则会被忽略：
   * 规则显示存在，入站仍按默认 BlockInbound 拦截（症状：ICMP/其他放行端口可达，唯独本工具端口不通）。
   * 检测到时临时开启本地规则合并并记录原始值，退出时还原。
   */
  ensureRuleEffective() {
    const q = runPS('Get-NetFirewallProfile | Select-Object Name, AllowLocalFirewallRules | ConvertTo-Json -Compress');
    let profiles;
    try {
      profiles = JSON.parse(q.stdout);
      if (!Array.isArray(profiles)) profiles = [profiles]; // 单个配置文件时 ConvertTo-Json 不返回数组
    } catch {
      log.warn('无法读取防火墙配置文件策略（Get-NetFirewallProfile 失败），若客户端连不上请手动检查防火墙策略');
      return;
    }
    // GpoBoolean 枚举经 ConvertTo-Json 序列化为数字：0=False（本地规则被忽略） 1=True 2=Any（未配置，正常态）
    // 兼容部分环境输出布尔/字符串形式的情形
    const ignored = profiles.filter((p) => {
      if (!p) return false;
      const v = String(p.AllowLocalFirewallRules).toLowerCase();
      return v === '0' || v === 'false';
    });
    if (!ignored.length) return;

    const names = ignored.map((p) => p.name).join(' / ');
    const setPs = ignored
      .map((p) => `Set-NetFirewallProfile -Name '${p.name}' -AllowLocalFirewallRules $true`)
      .join('; ');
    const s = runPS(setPs);
    if (s.code !== 0) {
      log.error(`防火墙策略忽略本地规则，且开启本地规则合并失败：${(s.stderr || s.stdout || '未知原因').split(/\r?\n/)[0]}`);
      log.warn(`请用本地安全策略 (secpol.msc) 手动放行入站 TCP ${PAIR_HTTP_PORT}，或联系管理员处理`);
      return;
    }
    this.fwMergePrev = ignored.map((p) => ({ name: p.name }));
    log.warn(`检测到防火墙策略忽略本地规则（${names}），已临时开启本地规则合并使放行规则生效，退出时自动还原`);
    log.warn('若本机属于域管控，此修改可能被组策略刷新覆盖；届时请用 secpol.msc 放行该端口或由管理员处理');
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
    if (this.fwMergePrev) {
      const ps = this.fwMergePrev
        .map((p) => `Set-NetFirewallProfile -Name '${p.name}' -AllowLocalFirewallRules $false`)
        .join('; ');
      const r = runPS(ps);
      if (r.code === 0) log.info('已还原防火墙本地规则合并策略');
      else log.warn('还原防火墙本地规则合并策略失败，请手动执行 Get-NetFirewallProfile 检查');
      this.fwMergePrev = null;
    }
  }
}

module.exports = { PairServer };
