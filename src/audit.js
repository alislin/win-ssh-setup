'use strict';

const fs = require('fs');
const path = require('path');
const { run, runPS } = require('./exec');
const { isAdmin, isAdminGroup, sshdPath, PROGRAM_DATA, userInfo } = require('./env');
const { fingerprint, parseKeyFile, authFilePaths, isValidPubLine } = require('./keymgr');
const install = require('./install');

function escapePs(s) {
  return String(s).replace(/'/g, "''");
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 解析 sshd_config（去掉注释后区分全局作用域与 Match Group administrators 块作用域）。
 */
function parseConfig(configPath) {
  const cfg = {
    exists: false,
    matchActive: false,
    globalKeysFile: null,
    blockKeysFile: null,
    globalPubkeyAuth: null,
    blockPubkeyAuth: null,
    ports: [],
    allowUsers: [], denyUsers: [], allowGroups: [], denyGroups: [],
    blockAllowUsers: [], blockDenyUsers: [], blockAllowGroups: [], blockDenyGroups: [],
  };
  if (!fs.existsSync(configPath)) return cfg;
  cfg.exists = true;
  let inBlock = false;
  for (const raw of fs.readFileSync(configPath, 'utf8').split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    if (/^Match\s+Group\s+administrators/i.test(line)) {
      inBlock = true;
      cfg.matchActive = true;
      continue;
    }
    if (/^Match\b/i.test(line)) {
      inBlock = false;
      continue;
    }
    const m = /^([\w-]+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    const g = inBlock ? 'block' : 'global';
    if (key === 'authorizedkeysfile') {
      if (g === 'global') cfg.globalKeysFile = val; else cfg.blockKeysFile = val;
    } else if (key === 'pubkeyauthentication') {
      if (g === 'global') cfg.globalPubkeyAuth = val.toLowerCase(); else cfg.blockPubkeyAuth = val.toLowerCase();
    } else if (key === 'port' && g === 'global') {
      cfg.ports.push(...val.split(/\s+/));
    } else if (key === 'allowusers') {
      (g === 'global' ? cfg.allowUsers : cfg.blockAllowUsers).push(...val.split(/\s+/));
    } else if (key === 'denyusers') {
      (g === 'global' ? cfg.denyUsers : cfg.blockDenyUsers).push(...val.split(/\s+/));
    } else if (key === 'allowgroups') {
      (g === 'global' ? cfg.allowGroups : cfg.blockAllowGroups).push(...val.split(/\s+/));
    } else if (key === 'denygroups') {
      (g === 'global' ? cfg.denyGroups : cfg.blockDenyGroups).push(...val.split(/\s+/));
    }
  }
  return cfg;
}

/** 判定 sshd 实际会读取哪个授权文件 */
function resolveExpectedKeysFile(cfg, adminGroup, home) {
  const paths = authFilePaths();
  if (adminGroup && cfg.matchActive) {
    return { file: paths.admin, source: 'Match Group administrators 启用 → administrators_authorized_keys' };
  }
  if (cfg.globalKeysFile) {
    const v = cfg.globalKeysFile;
    if (/__PROGRAMDATA__\/ssh\/administrators_authorized_keys/i.test(v)) {
      return { file: paths.admin, source: '全局 AuthorizedKeysFile → administrators_authorized_keys', custom: true };
    }
    if (/\.ssh\/authorized_keys/i.test(v)) {
      return { file: paths.user, source: '全局 AuthorizedKeysFile → 用户 authorized_keys', custom: true };
    }
    const p = v.replace(/__PROGRAMDATA__/ig, PROGRAM_DATA).replace(/%h/gi, home);
    return { file: p, source: `全局 AuthorizedKeysFile（自定义）→ ${p}`, custom: true };
  }
  return { file: paths.user, source: '默认 → 用户 authorized_keys' };
}

/** 当前用户组归属（名称 + SID 两个维度） */
function currentUserGroups() {
  const r = run('whoami.exe', ['/groups']);
  const sids = new Set((r.stdout.match(/S-1-5-[\d-]+/g) || []).map((s) => s.toLowerCase()));
  const names = new Set();
  for (const line of r.stdout.split(/\r?\n/)) {
    const m = /^\s*"?([^\s*][^*]*?)"?\s{2,}/.exec(line);
    if (m) names.add(m[1].replace(/"/g, '').toLowerCase());
  }
  return { sids, names };
}

/** sshd_config 的 user@host / 通配符用户匹配 */
function userMatchesConfig(entry, user) {
  const name = String(entry).split('@')[0];
  if (name === user) return true;
  if (/[*?]/.test(name)) {
    const rx = new RegExp('^' + escapeRegExp(name).replace(/\\\*/g, '.*').replace(/\\\?/g, '.') + '$', 'i');
    return rx.test(user);
  }
  return false;
}

/** 解析 SDDL，返回允许访问的账户集合与受保护标志 */
function parseSddl(sddl) {
  const aceRe = /\(([^)]+)\)/g;
  const allows = [];
  let m;
  while ((m = aceRe.exec(sddl))) {
    const fields = m[1].split(';');
    if (fields[0] !== 'A') continue;
    allows.push({ rights: fields[2] || '', account: (fields[4] || '').toLowerCase() });
  }
  return { allows, protected: undefined };
}

const ACL_OK_ACCOUNTS = new Set(['sy', '*s-1-5-18', 'ba', '*s-1-5-32-544']);
const ACL_BROAD_ACCOUNTS = new Set(['wd', 'au', 'bu', '*s-1-1-0', '*s-1-5-11', '*s-1-5-32-545']);

/** 判断 SDDL rights 字段是否含写入能力（字母码或数字掩码） */
function isWriteish(rights) {
  if (/FA|FW|WD(?![0-9A-Fa-f])/.test(rights)) return true;
  if (/^[0-9A-Fa-f]+$/.test(rights)) {
    const mask = parseInt(rights, 16) || 0;
    const WRITE_BITS = 0x40000000 | 0x2 | 0x4 | 0x100 | 0x40000 | 0x80000;
    return (mask & WRITE_BITS) !== 0;
  }
  return false;
}

/** 读取一个/多个路径的 SDDL */
function getSdls(paths) {
  const list = paths.map((p) => `'${escapePs(p)}'`).join(',');
  const r = runPS(`foreach ($p in @(${list})) { try { $a = Get-Acl -LiteralPath $p; 'SDDL<' + $p + '>' + $a.Sddl } catch { 'SDDL<' + $p + '>MISSING' } }`);
  const map = {};
  const re = /^SDDL<(.+?)>(.*)$/;
  for (const line of r.stdout.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (m) map[m[1]] = m[2];
  }
  return map;
}

/**
 * 配置体检（无连接，纯配置层检查）：按当前配置判断免密登录是否应可生效。
 * @param {object} opts
 * @param {string[]} [opts.pubKeys] 待检公钥（配对模式传刚部署的那把；密钥管理传全部）
 * @param {(item:{name,status,detail,fixId?})=>void} [opts.onStep]
 * @returns {Promise<{ok:boolean, checks:Array, failures:number, warnings:number}>}
 */
async function runAudit({ pubKeys = [], onStep } = {}) {
  const { user, home } = userInfo();
  const adminGroup = isAdminGroup();
  const paths = authFilePaths();
  const configPath = path.join(PROGRAM_DATA, 'ssh', 'sshd_config');
  const cfg = parseConfig(configPath);
  const checks = [];
  const TOTAL = 11;
  let i = 0;

  const emit = (title, res) => {
    i++;
    const item = {
      name: `[体检] ${i}/${TOTAL} ${title}`,
      status: res.status,
      detail: res.detail || '',
      fixId: res.fixId || null,
    };
    checks.push(item);
    if (onStep) onStep(item);
  };
  const doCheck = async (title, fn) => {
    try {
      emit(title, (await fn()) || { status: 'OK', detail: '' });
    } catch (e) {
      emit(title, { status: 'FAIL', detail: (e && e.message) || String(e) });
    }
  };

  // 1. 公钥位置与配置一致性
  await doCheck('公钥位置与配置一致性', async () => {
    if (!pubKeys.length) return { status: 'SKIP', detail: '本机无待检公钥' };
    const expected = resolveExpectedKeysFile(cfg, adminGroup, home);
    if (expected.file === paths.admin && !isAdmin()) {
      return { status: 'SKIP', detail: '管理员授权文件需管理员权限读取，跳过位置检查' };
    }
    const parsed = parseKeyFile(expected.file);
    if (!parsed.readable) return { status: 'SKIP', detail: '无法读取授权文件（需要管理员权限）' };
    const fps = new Set(parsed.keys.map((k) => k.fingerprint));
    const lines = new Set(parsed.keys.map((k) => k.pubLine));
    const missing = pubKeys.filter((pk) => {
      const fp = fingerprint(pk);
      return !fps.has(fp) && !lines.has(pk.trim());
    });
    if (missing.length === 0) {
      return { status: 'OK', detail: `本机用户读取 ${expected.source}${expected.custom ? '（自定义配置）' : ''}` };
    }
    return {
      status: 'FAIL',
      detail: `key 不在其读取的文件 ${expected.file}（${expected.source}），建议重新部署`,
    };
  });

  // 2. 管理员授权文件 ACL
  await doCheck('管理员授权文件 ACL', async () => {
    if (!adminGroup) return { status: 'SKIP', detail: '当前用户非管理员组' };
    if (!fs.existsSync(paths.admin)) return { status: 'SKIP', detail: '文件不存在' };
    // ACL 被正确收紧后，非管理员进程连读取都会被拒绝，因此非管理员环境直接跳过
    if (!isAdmin()) return { status: 'SKIP', detail: '非管理员环境，跳过（读取该文件 ACL 需要管理员权限）' };
    const sdls = getSdls([paths.admin]);
    const sddl = sdls[paths.admin] || '';
    if (!sddl || sddl === 'MISSING') return { status: 'WARN', detail: '无法读取 ACL' };
    const { allows } = parseSddl(sddl);
    const bad = allows.filter((a) => !ACL_OK_ACCOUNTS.has(a.account));
    const r = runPS(`$a = Get-Acl -LiteralPath '${escapePs(paths.admin)}'; 'PROTECTED=' + $a.AreAccessRulesProtected`);
    const protectedFlag = /PROTECTED=(\w+)/.exec(r.stdout);
    const isProtected = protectedFlag && protectedFlag[1] === 'True';
    if (bad.length) {
      return {
        status: 'FAIL',
        detail: `存在过宽权限（${bad.map((b) => b.account).join(', ')}），sshd 会拒绝读取该文件`,
        fixId: 'acl',
      };
    }
    if (!isProtected) {
      return { status: 'WARN', detail: '继承未禁用，父目录权限变更可能引入过宽权限', fixId: 'acl' };
    }
    return { status: 'OK', detail: '仅 Administrators/SYSTEM，继承已禁用' };
  });

  // 3. 用户文件与 .ssh 权限
  await doCheck('用户文件与 .ssh 权限', async () => {
    const targets = [paths.user, path.dirname(paths.user)].filter((p) => fs.existsSync(p));
    if (!targets.length) return { status: 'SKIP', detail: '用户授权文件不存在' };
    const sdls = getSdls(targets);
    const broad = [];
    for (const t of targets) {
      const { allows } = parseSddl(sdls[t] || '');
      for (const a of allows) {
        if (ACL_BROAD_ACCOUNTS.has(a.account) && isWriteish(a.rights)) broad.push(`${t}: ${a.account}`);
      }
    }
    if (broad.length) {
      return { status: 'WARN', detail: `检测到宽泛写权限（${broad.join('; ')}），可能导致 sshd 拒绝读取`, fixId: null };
    }
    return { status: 'OK', detail: '未发现宽泛写权限' };
  });

  // 4. PubkeyAuthentication
  await doCheck('PubkeyAuthentication', async () => {
    let val = cfg.globalPubkeyAuth;
    let scope = '全局';
    if (adminGroup && cfg.matchActive && cfg.blockPubkeyAuth) {
      val = cfg.blockPubkeyAuth;
      scope = 'Match Group administrators 块';
    }
    if (!val) return { status: 'OK', detail: '未显式配置（默认 yes）' };
    if (val === 'no') return { status: 'FAIL', detail: `${scope} 显式设为 no，公钥认证被关闭`, fixId: null };
    return { status: 'OK', detail: `${scope} = ${val}` };
  });

  // 5. AllowUsers / DenyUsers / AllowGroups / DenyGroups
  await doCheck('Allow/Deny 用户限制', async () => {
    const lists = {
      allowUsers: [...cfg.allowUsers, ...(adminGroup && cfg.matchActive ? cfg.blockAllowUsers : [])],
      denyUsers: [...cfg.denyUsers, ...(adminGroup && cfg.matchActive ? cfg.blockDenyUsers : [])],
      allowGroups: [...cfg.allowGroups, ...(adminGroup && cfg.matchActive ? cfg.blockAllowGroups : [])],
      denyGroups: [...cfg.denyGroups, ...(adminGroup && cfg.matchActive ? cfg.blockDenyGroups : [])],
    };
    if (lists.denyUsers.some((e) => userMatchesConfig(e, user))) {
      return { status: 'FAIL', detail: `用户 ${user} 被 DenyUsers 拒绝`, fixId: null };
    }
    if (lists.denyGroups.length) {
      const groups = currentUserGroups();
      const denied = lists.denyGroups.find((g) => groups.names.has(g.toLowerCase()) || groups.sids.has(g.toLowerCase()));
      if (denied) return { status: 'FAIL', detail: `用户所在组被 DenyGroups 拒绝：${denied}`, fixId: null };
    }
    if (lists.allowUsers.length) {
      const ok = lists.allowUsers.some((e) => userMatchesConfig(e, user));
      if (!ok) return { status: 'FAIL', detail: `AllowUsers 白名单未包含 ${user}`, fixId: null };
      return { status: 'OK', detail: `AllowUsers 包含 ${user}` };
    }
    if (lists.allowGroups.length) {
      const groups = currentUserGroups();
      const ok = lists.allowGroups.find((g) => groups.names.has(g.toLowerCase()) || groups.sids.has(g.toLowerCase()));
      if (!ok) return { status: 'FAIL', detail: `AllowGroups 白名单不含用户所在组`, fixId: null };
      return { status: 'OK', detail: `AllowGroups 匹配组：${ok}` };
    }
    return { status: 'SKIP', detail: '未配置用户限制' };
  });

  // 6. sshd 配置语法
  await doCheck('sshd 配置语法 (sshd -t)', async () => {
    const exe = sshdPath();
    if (!exe) return { status: 'SKIP', detail: '未找到 sshd.exe' };
    // sshd -t 需要读取主机私钥，非管理员环境会误报 no hostkeys，直接跳过
    if (!isAdmin()) return { status: 'SKIP', detail: '非管理员环境，跳过（sshd -t 需读取主机私钥）' };
    const r = run(exe, ['-t']);
    if (r.code !== 0) return { status: 'FAIL', detail: r.stderr || r.stdout || '校验未通过' };
    return { status: 'OK', detail: '配置合法' };
  });

  // 7. sshd 服务状态
  await doCheck('sshd 服务状态', async () => {
    const r = runPS(`$s = Get-Service -Name sshd -ErrorAction SilentlyContinue; if ($s) { 'STATUS=' + $s.Status + ';START=' + $s.StartType } else { 'STATUS=MISSING' }`);
    const m = /STATUS=(\w+);START=(\w+)/.exec(r.stdout);
    if (!m) return { status: 'FAIL', detail: 'sshd 服务未注册，请重新安装 OpenSSH Server', fixId: 'service' };
    if (m[1] !== 'Running') return { status: 'FAIL', detail: `服务状态 ${m[1]}`, fixId: 'service' };
    return { status: 'OK', detail: `Running（启动类型 ${m[2]}）` };
  });

  // 8. 主机密钥
  await doCheck('主机密钥', async () => {
    const dir = path.join(PROGRAM_DATA, 'ssh');
    let hostKeys = [];
    if (fs.existsSync(dir)) {
      hostKeys = fs.readdirSync(dir).filter((f) => /^ssh_host_.+_key$/.test(f) && !f.endsWith('.pub'));
    }
    if (!hostKeys.length) {
      return { status: 'FAIL', detail: '无主机密钥（重启 sshd 服务会自动生成）', fixId: 'hostkeys' };
    }
    return { status: 'OK', detail: hostKeys.map((f) => f.replace(/^ssh_host_|_key$/g, '')).join(' / ') };
  });

  // 9. 账户启用状态
  await doCheck('账户启用状态', async () => {
    const r = runPS(`try { $u = Get-LocalUser -Name '${escapePs(user)}' -ErrorAction Stop; 'ENABLED=' + $u.Enabled } catch { 'ENABLED=NOTFOUND' }`);
    const m = /ENABLED=(\w+)/.exec(r.stdout);
    if (!m) return { status: 'WARN', detail: '无法查询账户状态' };
    if (m[1] === 'True') return { status: 'OK', detail: `${user} 已启用` };
    if (m[1] === 'False') return { status: 'FAIL', detail: `账户 ${user} 已被禁用，任何认证方式都无法登录`, fixId: null };
    return { status: 'WARN', detail: '未找到本地账户对象' };
  });

  // 10. 端口与防火墙配置
  await doCheck('端口与防火墙配置', async () => {
    const ports = cfg.ports.length ? [...new Set(cfg.ports)] : ['22'];
    const portArgs = ports.map((p) => `'${p}'`).join(',');
    const r = runPS(
      `$ports = @(${portArgs}); $matched = @(); ` +
      `try { Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop | ` +
      `Get-NetFirewallPortFilter -ErrorAction Stop | ForEach-Object { $lp = @($_.LocalPort); foreach ($p in $ports) { if ($lp -contains $p) { $matched += $p } } } } catch {} ` +
      `'MATCHED=' + (($matched | Select-Object -Unique) -join ',')`,
    );
    const m = /MATCHED=(.*)/.exec(r.stdout);
    const matched = m && m[1] ? m[1].split(',').filter(Boolean) : [];
    if (ports.every((p) => matched.includes(p))) {
      return { status: 'OK', detail: `端口 ${ports.join('/')} 已放行` };
    }
    return {
      status: 'WARN',
      detail: `未发现端口 ${ports.join('/')} 的入站放行规则（若防火墙开启会拦截连接），仅配置层面提示`,
      fixId: ports.includes('22') ? 'firewall' : null,
    };
  });

  // 11. 微软账户 Match 风险
  await doCheck('微软账户 Match 风险', async () => {
    if (adminGroup && cfg.matchActive) {
      return {
        status: 'WARN',
        detail: 'Match Group administrators 处于启用状态：微软在线账户场景下可能因 SID 解析失败导致公钥认证失效，建议部署修补（注释该规则）',
        fixId: null,
      };
    }
    return { status: 'OK', detail: adminGroup ? 'Match 规则已注释/未启用' : '当前用户非管理员组，不适用' };
  });

  const failures = checks.filter((c) => c.status === 'FAIL').length;
  const warnings = checks.filter((c) => c.status === 'WARN').length;
  return { ok: failures === 0, checks, failures, warnings };
}

/**
 * 一键修复（体检项给出的 fixId）。
 * @returns {Promise<{ok:boolean, msg:string}>}
 */
async function runFix(fixId) {
  if (fixId === 'acl') {
    const paths = authFilePaths();
    const ok = require('./keymgr').restoreAdminAcl(paths.admin);
    return { ok, msg: ok ? '已重新收紧管理员授权文件 ACL' : 'ACL 修复失败（需要管理员权限）' };
  }
  if (fixId === 'firewall') {
    const ok = await install.ensureFirewall22();
    return { ok, msg: ok ? '已添加防火墙放行规则' : '防火墙规则添加失败' };
  }
  if (fixId === 'service') {
    const r = runPS(`Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name sshd -ErrorAction SilentlyContinue; (Get-Service -Name sshd).Status`);
    const running = /Running/i.test(r.stdout);
    return { ok: running, msg: running ? 'sshd 已启动' : '服务启动失败，请查看系统事件日志' };
  }
  if (fixId === 'hostkeys') {
    const r = runPS(`Restart-Service -Name sshd -Force -ErrorAction SilentlyContinue; (Get-Service -Name sshd).Status`);
    const running = /Running/i.test(r.stdout);
    return { ok: running, msg: running ? 'sshd 已重启并生成主机密钥' : '重启失败' };
  }
  return { ok: false, msg: `未知修复项：${fixId}` };
}

module.exports = { runAudit, runFix, parseConfig };
