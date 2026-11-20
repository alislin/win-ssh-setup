'use strict';

const fs = require('fs');
const path = require('path');
const { userInfo } = require('./env');

/** 部署记录文件路径（与客户端密钥同在 ~/.ssh，客户端模式无需管理员权限即可读写） */
function bookPath() {
  const { home } = userInfo();
  return path.join(home, '.ssh', 'win-ssh-setup-servers.json');
}

/**
 * 读取全部部署记录（最新部署的排在最前）。
 * 文件不存在、内容损坏或格式不符时按空记录处理，不影响流程。
 * @returns {Array<{host:string, serverUser:string, serverHostname:string, fingerprint:string, deployedAt:string}>}
 */
function all() {
  try {
    const list = JSON.parse(fs.readFileSync(bookPath(), 'utf8'));
    return Array.isArray(list)
      ? list.filter((e) => e && typeof e.host === 'string' && typeof e.serverUser === 'string')
      : [];
  } catch {
    return [];
  }
}

/** 按 host 查找部署记录（不区分大小写），无记录返回 null */
function findByHost(host) {
  const h = String(host || '').toLowerCase();
  return all().find((e) => e.host.toLowerCase() === h) || null;
}

/**
 * 新增或更新某台服务器的部署记录（按 host 去重，最新记录排最前）。
 * @param {{host:string, serverUser:string, serverHostname:string, fingerprint:string, deployedAt:string}} entry
 */
function upsert(entry) {
  const rest = all().filter((e) => e.host.toLowerCase() !== String(entry.host).toLowerCase());
  const list = [entry, ...rest];
  fs.mkdirSync(path.dirname(bookPath()), { recursive: true });
  fs.writeFileSync(bookPath(), JSON.stringify(list, null, 2), 'utf8');
}

module.exports = { bookPath, all, findByHost, upsert };
