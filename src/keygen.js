'use strict';

const fs = require('fs');
const path = require('path');
const { run, resolveTool } = require('./exec');
const { userInfo } = require('./env');

function keyPaths() {
  const { home } = userInfo();
  const sshDir = path.join(home, '.ssh');
  const keyPath = path.join(sshDir, 'id_ed25519');
  return { sshDir, keyPath, pubPath: `${keyPath}.pub` };
}

/** 已存在的密钥对信息，不存在则返回 null */
function findKeyPair() {
  const { keyPath, pubPath } = keyPaths();
  if (fs.existsSync(keyPath) && fs.existsSync(pubPath)) {
    return { keyPath, pubPath, pubKey: fs.readFileSync(pubPath, 'utf8').trim() };
  }
  return null;
}

/** 删除现有密钥对（用于强制重新生成） */
function deleteKeyPair() {
  const { keyPath, pubPath } = keyPaths();
  for (const f of [keyPath, pubPath]) {
    try { fs.rmSync(f, { force: true }); } catch { /* 忽略 */ }
  }
}

/** 生成 ed25519 空口令密钥对 */
function createKeyPair() {
  const { sshDir, keyPath, pubPath } = keyPaths();
  fs.mkdirSync(sshDir, { recursive: true });
  const kg = resolveTool('ssh-keygen');
  if (!kg) throw new Error('未找到 ssh-keygen，请先在“设置 → 可选功能”中安装 OpenSSH 客户端');
  const { user, hostname } = userInfo();
  const r = run(kg, ['-t', 'ed25519', '-f', keyPath, '-N', '', '-C', `${user}@${hostname}`]);
  if (r.code !== 0) throw new Error(`ssh-keygen 失败：${r.stderr || r.stdout || '未知错误'}`);
  return { keyPath, pubPath, pubKey: fs.readFileSync(pubPath, 'utf8').trim() };
}

module.exports = { keyPaths, findKeyPair, deleteKeyPair, createKeyPair };
