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

/**
 * 生成 ed25519 密钥对。
 * @param {object} [opts]
 * @param {string} [opts.keyPath] 密钥文件路径（默认 ~/.ssh/id_ed25519）
 * @param {string} [opts.passphrase] 私钥口令（默认空 = 完全免密）
 * @param {string} [opts.comment] 公钥注释（默认 user@hostname）
 * @returns {{keyPath:string, pubPath:string, pubKey:string}}
 */
function createKeyPair(opts = {}) {
  const { keyPath: target = keyPaths().keyPath, passphrase = '', comment } = opts;
  const pubTarget = `${target}.pub`;
  fs.mkdirSync(path.dirname(target), { recursive: true });
  if (fs.existsSync(target) || fs.existsSync(pubTarget)) {
    throw new Error(`密钥文件已存在，拒绝覆盖：${target}`);
  }
  const kg = resolveTool('ssh-keygen');
  if (!kg) throw new Error('未找到 ssh-keygen，请先在“设置 → 可选功能”中安装 OpenSSH 客户端');
  const { user, hostname } = userInfo();
  const finalComment = comment !== undefined ? comment : `${user}@${hostname}`;
  const r = run(kg, ['-t', 'ed25519', '-f', target, '-N', passphrase, '-C', finalComment]);
  if (r.code !== 0) throw new Error(`ssh-keygen 失败：${r.stderr || r.stdout || '未知错误'}`);
  return { keyPath: target, pubPath: pubTarget, pubKey: fs.readFileSync(pubTarget, 'utf8').trim() };
}

module.exports = { keyPaths, findKeyPair, deleteKeyPair, createKeyPair };
