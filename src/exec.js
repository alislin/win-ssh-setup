'use strict';

const { spawnSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * 同步执行外部命令。
 * @returns {{code:number, stdout:string, stderr:string}}
 */
function run(cmd, args = [], opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', windowsHide: true, ...opts });
  return {
    code: r.status === null ? -1 : r.status,
    stdout: (r.stdout || '').trim(),
    stderr: (r.stderr || '').trim(),
  };
}

/** 同步执行 PowerShell 脚本 */
function runPS(psScript, opts = {}) {
  return run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psScript], opts);
}

/**
 * 异步执行命令，子进程输出直接透传到当前控制台（用于 winget 等自带进度条的安装器）。
 * @returns {Promise<number>} 退出码
 */
function pump(cmd, args = []) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { stdio: 'inherit', windowsHide: true });
    } catch (e) {
      return resolve(-1);
    }
    child.on('error', () => resolve(-1));
    child.on('close', (code) => resolve(code === null ? -1 : code));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 在 PATH 与常见安装目录中查找外部工具（ssh / ssh-keygen / winget 等）。
 * @returns {string|null} 可执行文件完整路径
 */
function resolveTool(name) {
  const w = run('where.exe', [name]);
  if (w.code === 0 && w.stdout) {
    const first = w.stdout.split(/\r?\n/)[0].trim();
    if (first && fs.existsSync(first)) return first;
  }
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const pf = process.env.ProgramFiles || 'C:\\Program Files';
  const candidates = [
    path.join(sysRoot, 'System32', 'OpenSSH', `${name}.exe`),
    path.join(pf, 'OpenSSH', `${name}.exe`),
  ];
  return candidates.find((p) => fs.existsSync(p)) || null;
}

module.exports = { run, runPS, pump, sleep, resolveTool };
