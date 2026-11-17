'use strict';

const { run, resolveTool } = require('./exec');

/**
 * 用 BatchMode 试连验证免密登录是否生效（若仍需要密码会立即失败）。
 * @returns {{ok:boolean, msg:string}}
 */
function verifyPasswordless({ user, host }) {
  const ssh = resolveTool('ssh');
  if (!ssh) return { ok: false, msg: '未找到 ssh 客户端，无法自动验证' };
  const r = run(
    ssh,
    ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=accept-new', `${user}@${host}`, 'exit'],
    { timeout: 30000 },
  );
  if (r.code === 0) return { ok: true, msg: '免密登录验证通过' };
  const firstErr = (r.stderr || r.stdout || '').split(/\r?\n/)[0];
  return { ok: false, msg: `验证失败（exit=${r.code}）${firstErr ? `：${firstErr}` : ''}` };
}

module.exports = { verifyPasswordless };
