'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { run } = require('./exec');
const { PROGRAM_DATA, isAdminGroup, userInfo } = require('./env');

const PUBKEY_RE =
  /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[A-Za-z0-9@.-]+|sk-[A-Za-z0-9@.-]+)\s+[A-Za-z0-9+/]+={0,2}(\s+\S.*)?$/;

/** 校验整段公钥内容（单行、支持的算法类型），用于配对请求校验 */
function validatePubKey(pub) {
  if (typeof pub !== 'string') return false;
  const line = pub.trim();
  if (!line || line.split(/\r?\n/).length !== 1) return false;
  return PUBKEY_RE.test(line);
}

/** 单行是否为有效公钥 */
function isValidPubLine(line) {
  return PUBKEY_RE.test(String(line || '').trim());
}

/**
 * 计算 OpenSSH 格式指纹：SHA256:base64(sha256(base64decode(keyblob)))，无填充。
 * 与 `ssh-keygen -lf` 输出一致，且可逐行精确对应（不受空行/注释行影响）。
 */
function fingerprint(pubLine) {
  const parts = String(pubLine || '').trim().split(/\s+/);
  if (parts.length < 2 || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[1])) return null;
  try {
    const blob = Buffer.from(parts[1], 'base64');
    if (!blob.length) return null;
    const hash = crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
    return `SHA256:${hash}`;
  } catch {
    return null;
  }
}

function algoName(pubLine) {
  const t = String(pubLine || '').trim().split(/\s+/)[0] || '';
  const map = {
    'ssh-ed25519': 'ED25519',
    'ssh-rsa': 'RSA',
    'ecdsa-sha2-nistp256': 'ECDSA-NISTP256',
    'ecdsa-sha2-nistp384': 'ECDSA-NISTP384',
    'ecdsa-sha2-nistp521': 'ECDSA-NISTP521',
    'sk-ssh-ed25519@openssh.com': 'SK-ED25519',
    'sk-ecdsa-sha2-nistp256@openssh.com': 'SK-ECDSA',
  };
  return map[t] || t;
}

function keyComment(pubLine) {
  const parts = String(pubLine || '').trim().split(/\s+/);
  return parts.length > 2 ? parts.slice(2).join(' ') : '';
}

function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** 解析授权文件：原始行 + 有效公钥列表（带行索引/指纹/算法/注释）+ 无法识别行数 */
function parseKeyFile(file) {
  const result = { file, exists: fs.existsSync(file), readable: true, lines: [], keys: [], invalidCount: 0, error: null };
  if (!result.exists) return result;
  try {
    result.lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  } catch (e) {
    // ACL 收紧后非管理员进程不可读（属正常状态），标记后由调用方友好提示
    result.readable = false;
    result.error = e.message;
    return result;
  }
  result.lines.forEach((line, lineIndex) => {
    const t = line.trim();
    if (!t) return;
    if (isValidPubLine(t)) {
      result.keys.push({
        lineIndex,
        pubLine: t,
        fingerprint: fingerprint(t),
        algo: algoName(t),
        comment: keyComment(t),
      });
    } else {
      result.invalidCount++;
    }
  });
  return result;
}

/** 本机两个授权文件路径 */
function authFilePaths() {
  const { home } = userInfo();
  return {
    user: path.join(home, '.ssh', 'authorized_keys'),
    admin: path.join(PROGRAM_DATA, 'ssh', 'administrators_authorized_keys'),
  };
}

/**
 * 服务端授权公钥清单（本机作为服务端收到的 key）。
 * 管理员文件仅在当前用户属管理员组时纳入（与部署行为一致）。
 */
function listServerKeys() {
  const paths = authFilePaths();
  const list = [{ label: '用户', scope: 'user', file: paths.user, ...parseKeyFile(paths.user) }];
  if (isAdminGroup()) {
    list.push({ label: '管理员', scope: 'admin', file: paths.admin, ...parseKeyFile(paths.admin) });
  }
  return list;
}

/** 备份任意文件为 <file>.bak.<时间戳>，文件不存在返回 null */
function backupFile(file) {
  if (!fs.existsSync(file)) return null;
  const backup = `${file}.bak.${timestamp()}`;
  fs.copyFileSync(file, backup);
  return backup;
}

/** 备份客户端密钥对（私钥 + 公钥） */
function backupClientKeys() {
  const { keyPaths } = require('./keygen');
  const { keyPath, pubPath } = keyPaths();
  const outs = [];
  for (const f of [keyPath, pubPath]) {
    const b = backupFile(f);
    if (b) outs.push(b);
  }
  return outs;
}

/** 按保留条件重写文件（先自动备份；不删除重建，ACL 随文件保留） */
function rewriteKeeping(file, parsed, dropSet) {
  const backup = backupFile(file);
  const kept = parsed.lines.filter((_, i) => !dropSet.has(i));
  let text = kept.join('\r\n');
  if (text.length && !text.endsWith('\n')) text += '\r\n';
  fs.writeFileSync(file, text, 'utf8');
  return backup;
}

/** 删除指定授权文件中的公钥行（先备份） */
function deleteServerKeys(entries) {
  const byFile = new Map();
  for (const e of entries) {
    if (!byFile.has(e.file)) byFile.set(e.file, new Set());
    byFile.get(e.file).add(e.lineIndex);
  }
  const backups = [];
  for (const [file, dropSet] of byFile) {
    const parsed = parseKeyFile(file);
    if (!parsed.exists) continue;
    if (!parsed.readable) throw new Error(`无法读取文件（需要管理员权限）：${file}`);
    backups.push(rewriteKeeping(file, parsed, dropSet));
  }
  return backups;
}

/** 清空授权文件（先备份；管理员文件清空后重新收紧 ACL） */
function clearServerFile(file) {
  const parsed = parseKeyFile(file);
  if (parsed.exists && !parsed.readable) throw new Error(`无法读取文件（需要管理员权限）：${file}`);
  const backup = backupFile(file);
  fs.writeFileSync(file, '', 'utf8');
  const paths = authFilePaths();
  if (file === paths.admin) restoreAdminAcl(file);
  return backup;
}

/** 收紧管理员授权文件 ACL（SID 写法，不受系统语言影响），需管理员权限 */
function restoreAdminAcl(file) {
  const r = run('icacls.exe', [file, '/inheritance:r', '/grant', '*S-1-5-32-544:F', '/grant', '*S-1-5-18:F']);
  return r.code === 0;
}

/**
 * 按指纹删除授权文件中的公钥（先逐文件备份），永不删除 keepFingerprint。
 * @returns {{removed:Array<{fingerprint:string,file:string,comment:string}>, backups:string[]}}
 */
function removeByFingerprints({ fingerprints, keepFingerprint, files }) {
  const want = new Set(fingerprints);
  const removed = [];
  const backups = [];
  for (const file of files) {
    const parsed = parseKeyFile(file);
    if (!parsed.exists) continue;
    if (!parsed.readable) throw new Error(`无法读取文件（需要管理员权限）：${file}`);
    const drop = new Set();
    for (const k of parsed.keys) {
      if (k.fingerprint && want.has(k.fingerprint) && k.fingerprint !== keepFingerprint) {
        drop.add(k.lineIndex);
        removed.push({ fingerprint: k.fingerprint, file, comment: k.comment });
      }
    }
    if (drop.size) backups.push(rewriteKeeping(file, parsed, drop));
  }
  return { removed, backups };
}

/**
 * 扫描"同主机旧公钥"：注释主机名与 clientHostname 相同、但指纹与当前部署不同的残留 key。
 * 用于更换 key 场景的清理提示。
 */
function scanStaleKeys({ clientHostname, currentFingerprint, files }) {
  const stale = [];
  if (!clientHostname) return stale;
  const hostRe = new RegExp(`@${escapeRegExp(clientHostname)}(\\s|$)`, 'i');
  for (const file of files) {
    const parsed = parseKeyFile(file);
    if (!parsed.exists) continue;
    for (const k of parsed.keys) {
      if (!k.fingerprint || k.fingerprint === currentFingerprint) continue;
      if (hostRe.test(k.comment)) {
        stale.push({ file, lineIndex: k.lineIndex, fingerprint: k.fingerprint, algo: k.algo, comment: k.comment });
      }
    }
  }
  return stale;
}

module.exports = {
  PUBKEY_RE,
  validatePubKey,
  isValidPubLine,
  fingerprint,
  algoName,
  keyComment,
  timestamp,
  parseKeyFile,
  authFilePaths,
  listServerKeys,
  backupFile,
  backupClientKeys,
  deleteServerKeys,
  clearServerFile,
  restoreAdminAcl,
  removeByFingerprints,
  scanStaleKeys,
};
