'use strict';

const { spawn } = require('child_process');
const path = require('path');

/** 是否带 --elevated 标记（表示本进程是提权后的新进程） */
function isElevatedRequested() {
  return process.argv.includes('--elevated');
}

/**
 * 通过 UAC 弹窗以管理员身份重新启动本工具（新开一个 cmd 窗口执行相同角色）。
 * 调用后原进程应自行退出。
 */
function relaunch(extraArgs = []) {
  const script = path.resolve(__dirname, 'cli.js');
  const role = process.argv[2] || '';
  const argsTail = ['--elevated', ...extraArgs].filter(Boolean).join(' ');
  const inner = `chcp 65001 >nul & title win-ssh-setup & node "${script}" ${role} ${argsTail}`.trim();
  const ps = `Start-Process -Verb RunAs -FilePath 'cmd.exe' -ArgumentList '/k ${inner.replace(/'/g, "''")}'`;
  const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], {
    stdio: 'ignore',
    windowsHide: true,
  });
  child.on('error', () => {});
  return child;
}

module.exports = { isElevatedRequested, relaunch };
