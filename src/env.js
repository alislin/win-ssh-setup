'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const { run } = require('./exec');

const SYSTEM_ROOT = process.env.SystemRoot || 'C:\\Windows';
const PROGRAM_FILES = process.env.ProgramFiles || 'C:\\Program Files';
const PROGRAM_DATA = process.env.ProgramData || 'C:\\ProgramData';

const SSHD_PATHS = [
  path.join(PROGRAM_FILES, 'OpenSSH', 'sshd.exe'),
  path.join(SYSTEM_ROOT, 'System32', 'OpenSSH', 'sshd.exe'),
];

/** 当前进程是否具有管理员权限 */
function isAdmin() {
  return run('net.exe', ['session']).code === 0;
}

/** 当前用户是否属于 Administrators 组（不受 UAC 令牌影响） */
function isAdminGroup() {
  const r = run('whoami.exe', ['/groups']);
  return r.code === 0 && /S-1-5-32-544/i.test(r.stdout);
}

/** 已安装的 sshd.exe 路径（winget MSI 版优先，其次系统内置版） */
function sshdPath() {
  return SSHD_PATHS.find((p) => fs.existsSync(p)) || null;
}

/** OpenSSH Server 是否已安装（sshd.exe 存在或 sshd 服务已注册） */
function sshInstalled() {
  return !!sshdPath() || run('sc.exe', ['query', 'sshd']).code === 0;
}

/** 本机所有局域网 IPv4 地址 */
function lanIPs() {
  const result = [];
  const ni = os.networkInterfaces();
  for (const name of Object.keys(ni)) {
    for (const addr of ni[name] || []) {
      if (addr.family === 'IPv4' && !addr.internal) result.push(addr.address);
    }
  }
  return result;
}

function userInfo() {
  return {
    user: process.env.USERNAME || os.userInfo().username,
    home: process.env.USERPROFILE || os.homedir(),
    hostname: os.hostname(),
  };
}

module.exports = {
  SYSTEM_ROOT,
  PROGRAM_FILES,
  PROGRAM_DATA,
  isAdmin,
  isAdminGroup,
  sshdPath,
  sshInstalled,
  lanIPs,
  userInfo,
};
