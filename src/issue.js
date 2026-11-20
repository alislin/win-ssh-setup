'use strict';

/**
 * 密钥颁发辅助：服务端为其他设备（手机/平板等）生成专用密钥对并部署公钥，
 * 私钥文件导出到桌面由用户自行拷贝导入，交付确认后即从服务器删除（零残留）。
 *
 * 公钥注释约定：user@host#issued:<label>
 * - # 分隔可避开 scanStaleKeys 的 @主机名+空白 匹配，防止颁发出去的 key 被误判为同主机残留
 * - [4] 密钥管理 凭 #issued: 前缀识别已颁发公钥（显示为〔已颁发→标签〕），无需额外记录文件
 */

const fs = require('fs');
const path = require('path');
const { runPS } = require('./exec');
const { userInfo } = require('./env');

/** 公钥注释中的已颁发标记（#issued:<label>，label 不含空白） */
const ISSUED_RE = /#issued:([^\s]+)/;

/** 从公钥注释提取已颁发标签；非颁发密钥返回 null */
function issuedLabelOf(comment) {
  const m = ISSUED_RE.exec(String(comment || ''));
  return m ? m[1] : null;
}

/**
 * 清洗设备标签：Windows 文件名非法字符/空白折叠为 -，压缩重复，去首尾点横线，限 32 字符。
 * 中文可用；返回 null 表示标签为空（不可用）。
 */
function sanitizeLabel(raw) {
  const s = String(raw || '')
    .replace(/[\s\\/:*?"<>|#\x00-\x1f]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[.\-]+|[.\-]+$/g, '')
    .slice(0, 32);
  return s || null;
}

let desktopCache = null;
/**
 * 桌面目录解析。GetFolderPath 结果经 Base64 回传，规避控制台代码页导致的
 * 中文路径乱码（GBK 管道输出按 UTF-8 解码必错）；兼容 OneDrive 重定向桌面。
 * 解析失败回退 %USERPROFILE%\Desktop（env 变量编码可靠）。
 */
function desktopDir() {
  if (desktopCache) return desktopCache;
  const r = runPS(`[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Environment]::GetFolderPath('Desktop')))`);
  let dir = '';
  try {
    dir = Buffer.from((r.stdout || '').trim(), 'base64').toString('utf8').trim();
  } catch { /* 解码失败走回退 */ }
  desktopCache = (r.code === 0 && dir && fs.existsSync(dir))
    ? dir
    : path.join(userInfo().home, 'Desktop');
  return desktopCache;
}

/** 标签对应的桌面密钥文件路径 { keyPath, pubPath } */
function issueKeyPaths(label) {
  const base = `issued-${label}`;
  return {
    keyPath: path.join(desktopDir(), base),
    pubPath: path.join(desktopDir(), `${base}.pub`),
  };
}

/** 标签是否与桌面已有文件冲突（ssh-keygen 不覆盖已有文件，需提前换名） */
function labelConflict(label) {
  const { keyPath, pubPath } = issueKeyPaths(label);
  return fs.existsSync(keyPath) || fs.existsSync(pubPath);
}

/** 在桌面生成已颁发密钥对（经 keygen.createKeyPair，拒绝覆盖已有文件） */
function generateIssuedKey({ label, passphrase = '', comment }) {
  const { keyPath } = issueKeyPaths(label);
  const keygen = require('./keygen');
  return keygen.createKeyPair({ keyPath, passphrase, comment });
}

/** 删除桌面上的已颁发密钥文件（含 .pub），返回实际删除的路径列表 */
function deleteIssuedFiles(paths) {
  const removed = [];
  for (const f of [paths.keyPath, paths.pubPath]) {
    try {
      if (fs.existsSync(f)) {
        fs.rmSync(f, { force: true });
        removed.push(f);
      }
    } catch { /* 删除失败时保留文件，由用户手动处理 */ }
  }
  return removed;
}

module.exports = {
  ISSUED_RE,
  issuedLabelOf,
  sanitizeLabel,
  desktopDir,
  issueKeyPaths,
  labelConflict,
  generateIssuedKey,
  deleteIssuedFiles,
};
