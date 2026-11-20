'use strict';

const fs = require('fs');
const path = require('path');
const { run, runPS } = require('./exec');
const { isAdminGroup, sshdPath, PROGRAM_DATA, userInfo } = require('./env');
const { fingerprint, scanStaleKeys } = require('./keymgr');

function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

/** 幂等追加公钥到授权文件，已存在则返回 SKIP */
function appendKeyDedupe(file, keyLine) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let existing = '';
  if (fs.existsSync(file)) existing = fs.readFileSync(file, 'utf8');
  if (existing.split(/\r?\n/).some((l) => l.trim() === keyLine)) {
    return { status: 'SKIP', detail: `${file}（公钥已存在）` };
  }
  if (existing.length && !existing.endsWith('\n')) existing += '\r\n';
  fs.writeFileSync(file, existing + keyLine + '\r\n', 'utf8');
  return file;
}

/**
 * 注释 sshd_config 中的 Match Group administrators 块（含块内 administrators_authorized_keys 行）。
 * 只处理未注释的行；返回是否发生修改。
 */
function patchConfig(original) {
  const eol = original.includes('\r\n') ? '\r\n' : '\n';
  const lines = original.split(/\r?\n/);
  const out = [];
  let inBlock = false;
  let changed = false;
  for (const line of lines) {
    if (/^\s*Match\s+Group\s+administrators/i.test(line)) {
      inBlock = true;
      if (/^\s*#/.test(line)) { out.push(line); continue; }
      out.push(`#${line}`);
      changed = true;
      continue;
    }
    if (inBlock && /^\s*Match\b/i.test(line)) inBlock = false;
    if (inBlock && /^\s*AuthorizedKeysFile\s+__PROGRAMDATA__\/ssh\/administrators_authorized_keys/i.test(line)) {
      if (/^\s*#/.test(line)) { out.push(line); continue; }
      out.push(`#${line}`);
      changed = true;
      continue;
    }
    out.push(line);
  }
  return { text: out.join(eol), changed };
}

/**
 * 六步部署管线（在服务器端提权环境执行，幂等可重复运行）。
 * @param {object} opts
 * @param {string} opts.pubKey 客户端公钥（单行）
 * @param {string} [opts.clientHostname] 客户端主机名（用于同主机旧 key 识别）
 * @param {(step:{name:string,status:string,detail:string})=>void} [opts.onStep] 每步回调
 * @returns {Promise<{ok:boolean, steps:Array, userKeysPath:string, adminKeysPath:string|null, configBackup:string|null, staleKeys:Array}>}
 */
async function runDeploy({ pubKey, clientHostname, onStep }) {
  const steps = [];
  let configBackup = null;
  let aborted = false;

  const emit = (s) => { steps.push(s); if (onStep) onStep(s); };
  const doStep = async (name, fn) => {
    if (aborted) return;
    try {
      const out = await fn();
      emit(typeof out === 'string'
        ? { name, status: 'OK', detail: out }
        : { name, status: out.status || 'OK', detail: out.detail || '' });
    } catch (e) {
      aborted = true;
      emit({ name, status: 'FAIL', detail: (e && e.message) || String(e) });
    }
  };

  const keyLine = pubKey.trim();
  const { home } = userInfo();
  const adminGroup = isAdminGroup();
  const userKeysPath = path.join(home, '.ssh', 'authorized_keys');
  const adminKeysPath = path.join(PROGRAM_DATA, 'ssh', 'administrators_authorized_keys');
  const configPath = path.join(PROGRAM_DATA, 'ssh', 'sshd_config');

  await doStep('1/6 追加公钥到用户 authorized_keys', async () => appendKeyDedupe(userKeysPath, keyLine));

  await doStep('2/6 追加公钥到管理员授权文件', async () => {
    if (!adminGroup) return { status: 'SKIP', detail: '当前用户不属于管理员组，无需' };
    return appendKeyDedupe(adminKeysPath, keyLine);
  });

  await doStep('3/6 收紧授权文件 ACL（仅 Administrators/SYSTEM）', async () => {
    if (!adminGroup) return { status: 'SKIP', detail: '非管理员组，跳过' };
    if (!fs.existsSync(adminKeysPath)) return { status: 'SKIP', detail: '文件不存在，跳过' };
    // 使用 SID 而非组名，避免非英文系统的本地化组名问题
    const r = run('icacls.exe', [adminKeysPath, '/inheritance:r', '/grant', '*S-1-5-32-544:F', '/grant', '*S-1-5-18:F']);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout || 'icacls 执行失败');
    return 'inheritance:r + Administrators:F + SYSTEM:F';
  });

  await doStep('4/6 修补 sshd_config（注释 Match Group administrators）', async () => {
    if (!fs.existsSync(configPath)) {
      return { status: 'SKIP', detail: '配置文件不存在（sshd 首次启动会自动生成默认配置），跳过' };
    }
    const original = fs.readFileSync(configPath, 'utf8');
    const { text, changed } = patchConfig(original);
    if (!changed) return { status: 'SKIP', detail: '规则不存在或已注释，无需修改' };
    configBackup = `${configPath}.bak.${timestamp()}`;
    fs.writeFileSync(configBackup, original, 'utf8');
    fs.writeFileSync(configPath, text, 'utf8');
    return `已备份至 ${configBackup}`;
  });

  await doStep('5/6 校验 sshd 配置 (sshd -t)', async () => {
    const exe = sshdPath();
    if (!exe) throw new Error('未找到 sshd.exe，请确认 OpenSSH Server 已安装');
    const r = run(exe, ['-t']);
    if (r.code !== 0) {
      if (configBackup && fs.existsSync(configBackup)) {
        fs.writeFileSync(configPath, fs.readFileSync(configBackup, 'utf8'), 'utf8');
      }
      throw new Error(`${r.stderr || r.stdout || '校验未通过'}（已回滚 sshd_config，未重启服务）`);
    }
    return '配置合法';
  });

  await doStep('6/6 重启 sshd 服务', async () => {
    // 先判断服务是否注册（避免 PowerShell 中文报错乱码导致无法识别原因）
    const r = runPS(
      `$s = Get-Service -Name sshd -ErrorAction SilentlyContinue; ` +
      `if (-not $s) { 'NO_SERVICE' } ` +
      `else { Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue; Restart-Service -Name sshd -Force; (Get-Service -Name sshd).Status }`
    );
    const st = r.stdout.trim();
    if (st === 'NO_SERVICE') {
      throw new Error('sshd 服务未注册（sshd.exe 存在但服务缺失，半安装状态）——请在服务器模式重新运行本工具，可自动注册并启动服务');
    }
    if (r.code !== 0 || !/Running/i.test(st)) {
      throw new Error(`服务状态异常：${st || r.stderr || '未知'}`);
    }
    return 'sshd 已重启并运行中';
  });

  // 部署成功后扫描同主机旧公钥（更换 key 场景的残留）
  let staleKeys = [];
  if (!aborted) {
    const files = [userKeysPath, ...(adminGroup ? [adminKeysPath] : [])];
    staleKeys = scanStaleKeys({
      clientHostname,
      currentFingerprint: fingerprint(keyLine),
      files,
    });
  }

  return {
    ok: !aborted,
    steps,
    userKeysPath,
    adminKeysPath: adminGroup ? adminKeysPath : null,
    configBackup,
    staleKeys,
  };
}

module.exports = { runDeploy, patchConfig };
