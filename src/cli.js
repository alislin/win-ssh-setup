'use strict';

const readline = require('readline');
const log = require('./log');
const { c } = require('./log');
const { PAIR_HTTP_PORT } = require('./config');
const env = require('./env');
const elevate = require('./elevate');
const keygen = require('./keygen');
const keymgr = require('./keymgr');
const install = require('./install');
const { runDeploy } = require('./deploy');
const { runAudit, runFix } = require('./audit');
const { PairServer } = require('./pair-server');
const { discover, submit, cleanup, destroyCode, preflightTcp } = require('./pair-client');
const { verifyPasswordless } = require('./verify');
const serverbook = require('./serverbook');
const { resolveTool } = require('./exec');
const { userInfo } = require('./env');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((res) => rl.question(q, res));
const pause = async () => { await ask(`${c.dim}\n按回车键退出...${c.reset}`); rl.close(); };

const confirmYes = (ans, def = true) => {
  const a = String(ans || '').trim().toLowerCase();
  if (!a) return def;
  return /^y(es)?$/.test(a);
};

/* ---------------- 公共流程 ---------------- */

/** 需要管理员权限的操作：未提权则弹 UAC 在新窗口继续 */
async function requireAdmin() {
  if (env.isAdmin()) return true;
  if (elevate.isElevatedRequested()) {
    log.error('未获得管理员权限（UAC 可能被取消）。请重新运行本工具并确认 UAC 弹窗。');
    return false;
  }
  log.warn('此操作需要管理员权限，正在弹出 UAC 提权窗口，请在弹窗中选择“是”...');
  elevate.relaunch();
  log.info('操作已在新的管理员窗口中继续，本窗口稍后自动关闭。');
  setTimeout(() => process.exit(0), 1500);
  return false;
}

/** 确保 OpenSSH Server 已安装且 sshd 正在运行（含安装询问与回退） */
async function ensureSshInstalled() {
  if (env.sshInstalled()) {
    const st = install.ensureServiceRunning();
    install.ensureFirewall22();
    if (st === 'Running') log.ok('OpenSSH Server 已在运行');
    else log.warn(`OpenSSH Server 服务状态：${st}（配置部署后第 6 步会再次尝试重启）`);
    return true;
  }
  const ans = await ask('未检测到 OpenSSH Server，是否现在安装（winget，约 10-60 秒）？[Y/n]: ');
  if (!confirmYes(ans)) {
    log.warn('已取消安装，无法继续部署');
    return false;
  }
  if (!(await install.installOpenSSH())) return false;
  const st = install.ensureServiceRunning();
  install.ensureFirewall22();
  if (st !== 'Running') {
    log.error(`sshd 服务未能启动（状态：${st}）`);
    return false;
  }
  log.ok('OpenSSH Server 安装完成，sshd 已运行');
  return true;
}

/** 取得用于部署的公钥：已有则询问复用，否则生成 ed25519 空口令密钥 */
async function ensurePubKey() {
  const kp = keygen.findKeyPair();
  if (kp) {
    const ans = await ask(`检测到已有密钥对 ${kp.keyPath}，直接使用？[Y/n]: `);
    if (confirmYes(ans)) return { ...kp, reused: true };
    const again = await ask('将删除并重新生成密钥对（旧密钥不可恢复），继续？[y/N]: ');
    if (!confirmYes(again, false)) {
      log.warn('已取消，继续使用现有密钥');
      return { ...kp, reused: true };
    }
    keygen.deleteKeyPair();
  }
  log.info('正在生成 ed25519 密钥对（口令留空，实现完全免密）...');
  const created = keygen.createKeyPair();
  log.ok(`密钥对已生成：${created.keyPath}`);
  return { ...created, reused: false };
}

/** 解析手动输入的 IP（可带端口） */
async function askAddress() {
  const raw = (await ask('请输入服务器 IP（可带端口，如 192.168.1.10 或 192.168.1.10:22887）: ')).trim();
  if (!raw) return null;
  let host = raw;
  let port = PAIR_HTTP_PORT;
  const m = /^(.+?):(\d+)$/.exec(raw);
  if (m) {
    host = m[1];
    port = parseInt(m[2], 10);
  }
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const isHostname = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$/.test(host);
  if ((!isIPv4 && !isHostname) || !port || port < 1 || port > 65535) {
    log.warn('地址格式不正确');
    return null;
  }
  return { host, port };
}

/** 打印配置体检总结论 */
function printAuditSummary(audit) {
  if (!audit) return;
  if (audit.ok && !audit.warnings) {
    log.ok('配置体检全部通过 —— 按当前配置，免密登录应可生效');
  } else if (audit.ok) {
    log.warn(`配置体检：${audit.warnings} 项警告，${audit.failures} 项失败 —— 存在警告项，详见上方`);
  } else {
    log.error(`配置体检：${audit.failures} 项失败 —— 按当前配置免密登录不可用，请按上方修复建议处理`);
  }
}

/* ---------------- [4] 密钥管理 ---------------- */

function renderKeyManager() {
  const { user } = userInfo();
  log.plain('');
  log.plain(`  ${c.bold}══ 密钥管理 ══${c.reset}   ${c.dim}当前用户: ${user}${c.reset}`);

  // 客户端密钥（本机身份）
  const ck = keygen.findKeyPair();
  log.plain(`  ${c.bold}── 客户端密钥（本机身份，用于连别人）──${c.reset}`);
  if (ck) {
    log.plain(`  K1  ${keymgr.algoName(ck.pubKey)}  ${c.cyan}${keymgr.fingerprint(ck.pubKey)}${c.reset}  ${keymgr.keyComment(ck.pubKey)}`);
    log.plain(`      ${c.dim}路径: ${ck.keyPath}${c.reset}`);
  } else {
    log.plain('  （未生成 —— 运行 [2] 客户端 或 [3] 本机自连 时自动生成）');
  }

  // 服务端授权公钥（部署到本机的）
  log.plain(`  ${c.bold}── 服务端授权公钥（部署到本机的，本机作为服务端）──${c.reset}`);
  const groups = keymgr.listServerKeys();
  const entries = [];
  let n = 1;
  for (const g of groups) {
    if (g.exists && g.readable === false) {
      log.plain(`  ${c.dim}${g.label}文件: ${g.file}`);
      log.plain(`  （存在但需要管理员权限读取，请以管理员身份运行后管理）${c.reset}`);
      continue;
    }
    log.plain(`  ${c.dim}${g.label}文件: ${g.file}${g.exists ? '' : '（不存在）'}${c.reset}`);
    for (const k of g.keys) {
      log.plain(`  [${n}] (${g.label}) ${k.algo}  ${c.cyan}${k.fingerprint}${c.reset}  ${k.comment}`);
      entries.push({ ...k, file: g.file, label: g.label, scope: g.scope });
      n++;
    }
    if (!g.keys.length) log.plain(`  ${c.dim}（空）${c.reset}`);
    if (g.invalidCount) log.plain(`  ${c.dim}（${g.invalidCount} 行注释/无法识别内容，删除操作不会触碰）${c.reset}`);
  }
  log.plain('');
  log.plain(' 操作：[c] 体检   [d] 删除授权公钥   [k] 清空授权文件   [b] 备份');
  log.plain('       [g] 重新生成客户端密钥   [r] 刷新   [0] 返回');
  return { ck, groups, entries };
}

async function roleKeyMgr() {
  for (;;) {
    const { ck, groups, entries } = renderKeyManager();
    const op = (await ask('请选择操作: ')).trim().toLowerCase();
    let again = true;
    if (op === 'c') await keyMgrAudit(entries);
    else if (op === 'd') await keyMgrDelete(entries);
    else if (op === 'k') await keyMgrClear(groups);
    else if (op === 'b') await keyMgrBackup(ck);
    else if (op === 'g') await keyMgrRegen(ck);
    else if (op === 'r') again = true;
    else if (op === '0' || op === 'q') again = false;
    else log.warn('无效选项');
    if (!again) return;
  }
}

/** 体检：针对所有已部署公钥 + 整机配置 */
async function keyMgrAudit(entries) {
  const pubKeys = entries.map((e) => e.pubLine);
  const audit = await runAudit({
    pubKeys,
    onStep: (s) => log.step(s),
  });
  printAuditSummary(audit);
  const fixables = [...new Set(audit.checks.filter((x) => x.fixId && x.status !== 'OK' && x.status !== 'SKIP').map((x) => x.fixId))];
  if (fixables.length) {
    const ans = await ask('检测到可自动修复项，是否尝试修复？[y/N]: ');
    if (confirmYes(ans, false)) {
      if (!env.isAdmin() && !(await requireAdmin())) return;
      for (const fixId of fixables) {
        const r = await runFix(fixId);
        log[r.ok ? 'ok' : 'error'](`修复 [${fixId}]：${r.msg}`);
      }
      log.info('重新体检...');
      const audit2 = await runAudit({ pubKeys, onStep: (s) => log.step(s) });
      printAuditSummary(audit2);
    }
  }
}

async function keyMgrDelete(entries) {
  if (!entries.length) {
    log.warn('没有可删除的授权公钥');
    return;
  }
  const raw = (await ask('请输入要删除的序号（可多个，如 1,3）: ')).trim();
  if (!raw) return;
  const picked = [];
  for (const part of raw.split(/[,，\s]+/)) {
    const idx = parseInt(part, 10);
    const e = entries.find((x) => x.lineIndex !== undefined && entries.indexOf(x) === idx - 1);
    if (!e) {
      log.warn(`序号 ${part} 无效`);
      return;
    }
    picked.push(e);
  }
  log.plain('  将删除：');
  for (const e of picked) log.plain(`   - (${e.label}) ${e.fingerprint}  ${e.comment}`);
  const needAdmin = picked.some((e) => e.scope === 'admin');
  if (needAdmin && !env.isAdmin() && !(await requireAdmin())) return;
  const ans = await ask('确认删除？[y/N]: ');
  if (!confirmYes(ans, false)) {
    log.warn('已取消');
    return;
  }
  const backups = keymgr.deleteServerKeys(picked.map((e) => ({ file: e.file, lineIndex: e.lineIndex })));
  log.ok(`已删除 ${picked.length} 个公钥（authorized_keys 即时生效，无需重启服务）`);
  for (const b of backups) log.info(`备份：${b}`);
}

async function keyMgrClear(groups) {
  const existing = groups.filter((g) => g.exists && g.readable !== false);
  if (existing.length !== groups.filter((g) => g.exists).length) {
    log.warn('部分授权文件需要管理员权限读取，如需清空请以管理员身份运行');
  }
  if (!existing.length) {
    log.warn('没有可清空的授权文件');
    return;
  }
  log.plain('  可清空的文件：');
  existing.forEach((g, i) => log.plain(`   [${i + 1}] ${g.label}文件  ${g.file}（${g.keys.length} 个公钥）`));
  const pick = parseInt((await ask('请选择文件序号: ')).trim(), 10);
  const g = existing[pick - 1];
  if (!g) {
    log.warn('已取消');
    return;
  }
  if (g.scope === 'admin' && !env.isAdmin() && !(await requireAdmin())) return;
  const ans = (await ask(`将清空 ${g.label}文件的全部 ${g.keys.length} 个公钥！本机无登录密码时可能导致无法再登录。输入 YES 确认: `)).trim();
  if (ans !== 'YES') {
    log.warn('已取消（需输入 YES）');
    return;
  }
  const backup = keymgr.clearServerFile(g.file);
  log.ok('已清空（即时生效，无需重启服务）');
  if (backup) log.info(`备份：${backup}`);
}

async function keyMgrBackup(ck) {
  const backups = keymgr.backupClientKeys();
  for (const g of keymgr.listServerKeys()) {
    const b = keymgr.backupFile(g.file);
    if (b) backups.push(b);
  }
  if (!backups.length) {
    log.warn('没有可备份的密钥文件');
    return;
  }
  log.ok(`已备份 ${backups.length} 个文件：`);
  for (const b of backups) log.info(b);
}

async function keyMgrRegen(ck) {
  if (!ck) {
    log.warn('尚未生成客户端密钥');
    return;
  }
  const ans = await ask('将删除并重新生成客户端密钥对（旧密钥自动备份、不可恢复），继续？[y/N]: ');
  if (!confirmYes(ans, false)) {
    log.warn('已取消');
    return;
  }
  const backups = keymgr.backupClientKeys();
  keygen.deleteKeyPair();
  const created = keygen.createKeyPair();
  log.ok(`新密钥对已生成：${created.keyPath}`);
  log.info(`新指纹：${keymgr.fingerprint(created.pubKey)}`);
  for (const b of backups) log.info(`旧密钥备份：${b}`);
  log.warn('旧公钥仍残留在各服务器上，重新运行 [2] 客户端配对时可自动检测并清理');
}

/* ---------------- [1] 服务器端 ---------------- */

async function roleServer() {
  const { user } = userInfo();
  log.info(`当前用户：${user}${env.isAdminGroup() ? '（管理员组：将同步部署 administrators_authorized_keys）' : ''}`);
  if (!(await requireAdmin())) return;
  if (!(await ensureSshInstalled())) return;

  const server = new PairServer();
  server.start();
  const ips = env.lanIPs();
  log.plain('');
  log.plain(`  ${c.bold}══ 等待客户端连接 ══${c.reset}`);
  log.plain(`  本机地址 : ${c.cyan}${ips.length ? ips.join('  ') : '未检测到局域网 IP（可让客户端手动输入主机名）'}${c.reset}   端口 : ${PAIR_HTTP_PORT}`);
  log.plain(`  配对码   : ${c.green}${c.bold}${server.displayCode()}${c.reset}   ← 每 5 分钟自动轮换，配对成功后立即更新`);
  log.plain(`  快捷键   : ${c.bold}[p]${c.reset} 生成持久配对码（异地连接，不轮换）  ${c.bold}[d]${c.reset} 销毁持久码  ${c.bold}[q]${c.reset} 退出`);
  log.plain('  客户端配对后：自动部署 → 配置体检（无连接）→ 可选实测；按 Ctrl+C 退出（自动清理临时防火墙规则）');
  log.plain('');

  const cleanupAll = () => { server.stop(); process.exit(0); };
  process.on('SIGINT', cleanupAll);
  process.on('SIGBREAK', cleanupAll);
  process.on('exit', () => server.stop());

  // 等待客户端配对的同时监听快捷键：[p] 激活持久码（异地连接用） / [d] 销毁持久码 / [q] 退出
  rl.on('line', (line) => {
    const k = String(line || '').trim().toLowerCase();
    if (k === 'p') server.createPersistentCode();
    else if (k === 'd') server.destroyPersistentCode();
    else if (k === 'q') cleanupAll();
  });

  // 挂起等待客户端配对（Ctrl+C 或 [q] 退出），避免提前返回导致菜单循环继续
  await new Promise(() => {});
}

/* ---------------- [2] 客户端 ---------------- */

async function roleClient() {
  const { hostname } = userInfo();
  log.info(`本机 ${hostname}（客户端模式，无需管理员权限）`);
  if (!resolveTool('ssh')) {
    log.error('未找到 ssh 客户端，请先在“设置 → 可选功能”中安装 OpenSSH 客户端');
    return;
  }

  const pub = await ensurePubKey();
  log.ok(`使用公钥：${pub.pubPath}${pub.reused ? '（已有密钥）' : ''}`);

  let done = null;
  let target = null;
  let skipDiscovery = false;
  let already = null; // 免密预检通过时记录 {user, host}，跳过重复部署
  outer: for (;;) {
    // —— 选择目标：自动发现（可重扫）或手动输 IP ——
    if (!skipDiscovery) {
      log.info('正在搜索同一网络中等待配对的服务器（约 5 秒）...');
      for (;;) {
        const list = await discover(5000);
        if (list.length) {
          log.plain('  发现以下服务器：');
          list.forEach((s, i) => log.plain(`   [${i + 1}] ${s.hostname}  (${s.ip})`));
          const pick = (await ask(`请选择 [1-${list.length}]，或 [r] 重新扫描 / [m] 手动输入 IP / [0] 返回菜单: `)).trim().toLowerCase();
          if (pick === 'r') {
            log.info('正在重新扫描...');
            continue;
          }
          if (pick === '0' || pick === 'q') return;
          if (pick === 'm') {
            target = await askAddress();
            if (!target) continue;
            break;
          }
          const idx = parseInt(pick, 10);
          if (!idx || idx < 1 || idx > list.length) {
            log.warn('输入无效，请重试');
            continue;
          }
          target = { host: list[idx - 1].ip, port: list[idx - 1].httpPort };
          break;
        }
        log.warn('未自动发现服务器（可能被路由器/AP 隔离、广播被拦截，或服务器尚未启动）');
        const pick = (await ask('请选择: [r] 重新扫描 / [m] 手动输入 IP / [0] 返回菜单: ')).trim().toLowerCase();
        if (pick === 'r') {
          log.info('正在重新扫描...');
          continue;
        }
        if (pick === '0' || pick === 'q') return;
        if (pick === 'm' || pick === '') {
          target = await askAddress();
          if (!target) continue;
          break;
        }
        log.warn('输入无效，请重试');
      }
    }

    // —— 免密预检：已部署过的服务器若已可免密连接，跳过重复部署（不消耗配对码、服务器端零改动）——
    if (!skipDiscovery) {
      const rec = serverbook.findByHost(target.host);
      if (rec) {
        const t = new Date(rec.deployedAt);
        const when = rec.deployedAt && !Number.isNaN(t.getTime()) ? t.toLocaleString() : '未知时间';
        log.info(`本地有部署记录：${rec.host}（用户 ${rec.serverUser}，${when} 部署），正在检测是否已可免密连接（约几秒）...`);
        const pre = verifyPasswordless({ user: rec.serverUser, host: target.host });
        if (pre.ok) {
          log.ok(`该服务器已可免密登录（ssh ${rec.serverUser}@${target.host}），跳过重复部署`);
          already = { user: rec.serverUser, host: target.host };
          break;
        }
        log.info('免密预检未通过，继续正常配对流程');
      }
    }

    // —— 配对码：临时码 6 位（一次性）；持久码 8 位（不轮换，可重复使用）——
    let code = null;
    for (let i = 0; i < 3; i++) {
      const raw = (await ask('请输入服务器屏幕上显示的配对码（6~8 位数字）: ')).trim().replace(/\s+/g, '');
      if (/^\d{6,8}$/.test(raw)) { code = raw; break; }
      log.warn('配对码应为 6~8 位数字，请重试');
    }
    if (!code) {
      log.error('多次输入无效，退出');
      return;
    }

    // —— TCP 预检 + 提交 ——
    log.info(`正在连接 ${target.host}:${target.port} 并部署公钥（部署与体检步骤实时回传）...`);
    try {
      await preflightTcp(target, 8000);
      log.ok(`预检通过：TCP ${target.host}:${target.port} 可达`);
    } catch (e) {
      log.error(`预检失败：${e.message}`);
    }
    try {
      done = await submit({
        ...target,
        code,
        pubKey: pub.pubKey,
        onStep: (s) => log.step(s),
        onConnected: (status) => log.ok(`服务器已受理（HTTP ${status}），正在接收执行结果...`),
      });
      break;
    } catch (e) {
      log.error(`配对失败：${e.message}`);
    }

    // —— 失败重试菜单（临时码一次性需重输新码；持久码未变可直接重试）——
    const pick = (await ask('请选择: [n] 重输配对码（当前服务器） / [r] 重新扫描 / [m] 手动输 IP / [0] 返回菜单: ')).trim().toLowerCase();
    if (pick === 'n') { skipDiscovery = true; continue; }
    if (pick === 'r' || pick === 'm') { skipDiscovery = false; continue; }
    return;
  }
  // 免密预检通过：已可连接，未做任何部署，直接给出结论
  if (already) {
    log.plain('');
    log.plain(`  ${c.green}${c.bold}✔ 配置完成！${c.reset} 已可免密连接，本次未重新部署  实测${c.green}✔${c.reset}`);
    log.plain(`  测试命令：${c.cyan}ssh ${already.user}@${already.host}${c.reset}`);
    log.plain('');
    return;
  }
  if (!done.ok) {
    log.error(`服务器部署存在失败步骤：${done.error || '详情见服务器端日志'}`);
    return;
  }
  log.ok(`服务器 ${done.serverHostname} 部署完成，目标用户：${done.serverUser}`);

  // 保存部署记录：下次选择该服务器时先做免密预检，已可连接则跳过重复部署
  try {
    serverbook.upsert({
      host: target.host,
      serverUser: done.serverUser,
      serverHostname: done.serverHostname,
      fingerprint: fingerprintOf(pub.pubKey),
      deployedAt: new Date().toISOString(),
    });
  } catch (e) {
    log.warn(`部署记录保存失败（不影响本次使用）：${(e && e.message) || e}`);
  }

  printAuditSummary(done.audit);

  // 更换 key 场景：清理服务器上的同主机旧公钥（凭配对签发的会话令牌鉴权）
  if (done.sessionToken && done.staleKeys && done.staleKeys.length) {
    log.plain(`  ${c.yellow}检测到本机旧公钥 ${done.staleKeys.length} 个（更换密钥后残留）：${c.reset}`);
    for (const s of done.staleKeys) log.plain(`   - ${s.fingerprint}  ${s.comment}`);
    const ans = await ask('是否清理上述旧公钥？[Y/n]: ');
    if (confirmYes(ans)) {
      try {
        const r = await cleanup({
          ...target,
          sessionToken: done.sessionToken,
          fingerprints: done.staleKeys.map((s) => s.fingerprint),
          keepFingerprint: fingerprintOf(pub.pubKey),
          onStep: (s) => log.step(s),
        });
        if (r.ok) log.ok(`已清理 ${r.removed} 个旧公钥`);
        else log.error(`清理失败：${r.error || '未知'}`);
      } catch (e) {
        log.error(`清理失败：${e.message}`);
      }
    }
  }

  // 持久配对码场景：异地设置完成后可远程销毁，避免长期暴露（凭配对签发的会话令牌鉴权）
  if (done.sessionToken && done.persistent) {
    const ans = await ask('服务器正在使用持久配对码（不轮换、可重复使用），是否销毁它？[y/N]: ');
    if (confirmYes(ans, false)) {
      try {
        const r = await destroyCode({ ...target, sessionToken: done.sessionToken });
        if (r.destroyed) log.ok('已销毁服务器上的持久配对码（服务器已回到临时码模式）');
        else log.info('服务器当前没有激活的持久配对码');
      } catch (e) {
        log.error(`销毁失败：${e.message}`);
        log.info('可改在服务器端按 [d] 销毁；不销毁也不影响已完成的部署，进程退出时自动失效');
      }
    } else {
      log.info('已保留持久配对码，可继续配对其他设备；销毁可在服务器端按 [d]，或进程退出自动失效');
    }
  }

  // 实测（可选）
  const ans = await ask('是否实测连接确认免密登录？[Y/n]: ');
  let verified = false;
  if (confirmYes(ans)) {
    log.info(`正在验证免密登录 ssh ${done.serverUser}@${target.host} ...`);
    const v = verifyPasswordless({ user: done.serverUser, host: target.host });
    if (!v.ok) {
      log.error(v.msg);
      log.info('配置体检若全部通过，多为网络层问题；公钥已部署，可稍后手动测试');
    } else {
      verified = true;
      log.ok('实测通过');
    }
  }

  log.plain('');
  log.plain(`  ${c.green}${c.bold}✔ 配置完成！${c.reset} 部署${c.green}✔${c.reset} 体检${done.audit && done.audit.ok ? c.green + '✔' : c.yellow + '!' + c.reset}${verified ? ` 实测${c.green}✔${c.reset}` : ''}`);
  log.plain(`  测试命令：${c.cyan}ssh ${done.serverUser}@${target.host}${c.reset}`);
  if (done.paths && done.paths.configBackup) {
    log.plain(`  ${c.dim}sshd_config 备份：${done.paths.configBackup}${c.reset}`);
  }
  log.plain('');
}

/* ---------------- [3] 本机自连 ---------------- */

async function roleLocal() {
  const { user } = userInfo();
  log.info(`当前用户：${user}（本机自连模式）`);
  if (!(await requireAdmin())) return;
  if (!(await ensureSshInstalled())) return;

  const pub = await ensurePubKey();
  log.ok(`使用公钥：${pub.pubPath}${pub.reused ? '（已有密钥）' : ''}`);

  log.info('开始本机部署...');
  const r = await runDeploy({ pubKey: pub.pubKey, onStep: (s) => log.step(s) });
  if (!r.ok) {
    log.error('部署存在失败步骤，详见上方日志');
    return;
  }
  log.ok('部署完成');

  log.info('开始配置体检（无连接，纯配置层检查）...');
  const audit = await runAudit({ pubKeys: [pub.pubKey], onStep: (s) => log.step(s) });
  printAuditSummary(audit);

  const ans = await ask('是否实测连接确认免密登录？[Y/n]: ');
  let verified = false;
  if (confirmYes(ans)) {
    log.info(`正在验证免密登录 ssh ${user}@localhost ...`);
    const v = verifyPasswordless({ user, host: 'localhost' });
    if (!v.ok) {
      log.error(v.msg);
      log.info(`公钥已部署完成，可稍后手动测试：ssh ${user}@localhost`);
    } else {
      verified = true;
      log.ok('实测通过');
    }
  }

  log.plain('');
  log.plain(`  ${c.green}${c.bold}✔ 配置完成！${c.reset} 部署${c.green}✔${c.reset} 体检${audit.ok ? c.green + '✔' : c.yellow + '!' + c.reset}${verified ? ` 实测${c.green}✔${c.reset}` : ''}`);
  log.plain(`  测试命令：${c.cyan}ssh ${user}@localhost${c.reset}`);
  if (r.configBackup) log.plain(`  ${c.dim}sshd_config 备份：${r.configBackup}${c.reset}`);
  log.plain('');
}

/* ---------------- 入口 ---------------- */

function printMenu() {
  log.plain(' 请选择运行模式：');
  log.plain('   [1] 服务器端  —— 本机作为被连接的 SSH 服务器（需要管理员）');
  log.plain('   [2] 客户端    —— 本机发起连接，把本机公钥部署到对方');
  log.plain('   [3] 本机自连  —— 生成密钥并部署到本机（ssh localhost）');
  log.plain('   [4] 密钥管理  —— 客户端/服务端密钥查看、体检、删除、清空、备份');
  log.plain('   [0] 退出');
}

async function runRole(role) {
  if (role === 'server') await roleServer();
  else if (role === 'client') await roleClient();
  else if (role === 'keys') await roleKeyMgr();
  else await roleLocal();
}

async function main() {
  log.banner();
  const arg = (process.argv[2] || '').toLowerCase();
  const role = { server: 'server', client: 'client', local: 'local', keys: 'keys' }[arg] || null;

  // 显式传参：一次性执行，跑完退出（便于脚本调用）
  if (role) {
    await runRole(role);
    if (role !== 'server') await pause();
    else rl.close();
    return;
  }

  // 交互模式：主菜单循环，子流程返回后回到菜单，[0] 退出
  for (;;) {
    printMenu();
    const ans = (await ask('请选择 [0-4]: ')).trim().toLowerCase();
    if (ans === '0' || ans === 'q') break;
    const pick = { '1': 'server', '2': 'client', '3': 'local', '4': 'keys' }[ans];
    if (!pick) {
      log.warn('无效选项，请重新选择');
      continue;
    }
    await runRole(pick);
  }
  rl.close();
}

function fingerprintOf(pubKey) {
  return require('./keymgr').fingerprint(pubKey);
}

main().catch((e) => {
  log.error(`未预期的错误：${(e && e.stack) || e}`);
  process.exit(1);
});
