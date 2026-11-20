'use strict';

const log = require('./log');
const { run, runPS, pump } = require('./exec');
const { sshInstalled, sshdPath } = require('./env');

/** 通过 winget 安装 OpenSSH Preview（Microsoft.OpenSSH.Preview） */
async function installViaWinget() {
  const code = await pump('winget.exe', [
    'install', '--id', 'Microsoft.OpenSSH.Preview', '-e',
    '--accept-source-agreements', '--accept-package-agreements', '--silent',
  ]);
  return code === 0 && sshInstalled();
}

/** 回退方案：系统内置可选功能（走 Windows Update，无需外网源） */
function installViaCapability() {
  log.info('回退方案：通过系统可选功能安装 OpenSSH Server（Add-WindowsCapability）...');
  const r = runPS(`Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-String`);
  return r.code === 0 && sshInstalled();
}

/**
 * 安装 OpenSSH Server（winget 优先，失败回退 capability）。
 * @returns {Promise<boolean>}
 */
async function installOpenSSH() {
  log.info('通过 winget 安装 OpenSSH Preview（Microsoft.OpenSSH.Preview），请稍候...');
  if (await installViaWinget()) {
    log.ok('winget 安装成功');
    return true;
  }
  log.warn('winget 安装未成功，切换回退方案...');
  if (installViaCapability()) {
    log.ok('系统可选功能安装成功');
    return true;
  }
  log.error('OpenSSH Server 安装失败，请检查网络后手动安装：winget install "openssh preview"');
  return false;
}

/**
 * 确保 sshd 服务为自动启动且正在运行。
 * @returns {string} 服务状态（Running / Stopped / MISSING 等）
 */
function ensureServiceRunning() {
  const r = runPS([
    `Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue;`,
    `$s = Get-Service -Name sshd -ErrorAction SilentlyContinue;`,
    `if ($s -and $s.Status -ne 'Running') { Start-Service -Name sshd -ErrorAction SilentlyContinue; $s.Refresh(); }`,
    `if ($s) { 'STATUS=' + $s.Status } else { 'STATUS=MISSING' }`,
  ].join(' '));
  const m = /STATUS=(\w+)/.exec(r.stdout);
  return m ? m[1] : 'UNKNOWN';
}

/**
 * 注册 sshd Windows 服务（sshd.exe 存在但服务未注册的"半安装"状态修复）。
 * 参照 Win32-OpenSSH 官方 install-sshd.ps1 的做法：注册服务 + 事件日志支持；服务已存在时幂等跳过。
 * @returns {boolean} 服务可用（本次注册成功或本已存在）
 */
function registerSshService() {
  const exe = sshdPath();
  if (!exe) {
    log.error('未找到 sshd.exe，无法注册服务');
    return false;
  }
  const r = runPS([
    `$bin = '${exe.replace(/'/g, "''")}';`,
    `$s = Get-Service -Name sshd -ErrorAction SilentlyContinue;`,
    `if ($s) { 'EXISTS' }`,
    `else {`,
    `New-Service -Name sshd -DisplayName 'OpenSSH SSH Server' -BinaryPathName ('"' + $bin + '"') -StartupType Automatic -ErrorAction Stop | Out-Null;`,
    `$reg = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\OpenSSH';`,
    `New-Item -Path $reg -ErrorAction SilentlyContinue | Out-Null;`,
    `New-ItemProperty -Path $reg -Name EventMessageFile -Value "$env:SystemRoot\\Microsoft.NET\\Framework64\\v4.0.30319\\EventLogMessages.dll" -PropertyType String -ErrorAction SilentlyContinue | Out-Null;`,
    `'REGISTERED'`,
    `}`,
  ].join(' '));
  if (r.code === 0 && /(EXISTS|REGISTERED)/.test(r.stdout)) {
    log.ok(/EXISTS/.test(r.stdout) ? 'sshd 服务已存在，无需注册' : `已注册 sshd 服务（${exe}）`);
    return true;
  }
  log.error(`注册 sshd 服务失败：${(r.stderr || r.stdout || '未知原因').split(/\r?\n/)[0]}`);
  return false;
}

/** 确保防火墙放行 SSH 22 端口（OpenSSH-Server-In-TCP 规则） */
function ensureFirewall22() {
  const q = run('netsh.exe', ['advfirewall', 'firewall', 'show', 'rule', 'name=OpenSSH-Server-In-TCP']);
  if (q.code === 0) return true;
  const a = run('netsh.exe', [
    'advfirewall', 'firewall', 'add', 'rule', 'name=OpenSSH-Server-In-TCP',
    'dir=in', 'action=allow', 'protocol=TCP', 'localPort=22',
  ]);
  if (a.code === 0) log.ok('已添加防火墙规则放行 TCP 22 端口');
  else log.warn('添加防火墙规则失败，若无法连接请手动放行 TCP 22 端口');
  return a.code === 0;
}

module.exports = { installOpenSSH, ensureServiceRunning, ensureFirewall22, registerSshService };
