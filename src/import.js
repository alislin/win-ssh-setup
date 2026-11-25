'use strict';

/**
 * 公钥导入辅助：服务端把外部已有的公钥（粘贴文本 / .pub 文件）解析校验后
 * 部署到本机授权文件并即时生效（复用六步部署管线的 skipRestart 模式）。
 *
 * 公钥注释约定：#imported:<标签>
 * - 与 #issued:（密钥颁发）先例一致，# 分隔可避开 scanStaleKeys 的 @主机名+空白 匹配，
 *   防止导入的 key 被误判为同主机残留
 * - [4] 密钥管理 凭 #imported: 前缀识别外部导入公钥（显示为〔外部导入→标签〕）
 * - 指纹由 keyblob 决定，追加/替换注释不影响指纹
 * - 导入时自动识别注释中已有的标签（detectTag：#imported: 标记优先，其次末尾单标记）
 */

const fs = require('fs');
const keymgr = require('./keymgr');
const issue = require('./issue');

/** 公钥注释中的导入标记（#imported:<label>，label 不含空白） */
const IMPORTED_RE = /#imported:([^\s]+)/;

/** 从公钥注释提取导入标签；非导入公钥返回 null */
function importedLabelOf(comment) {
  const m = IMPORTED_RE.exec(String(comment || ''));
  return m ? m[1] : null;
}

/** 清理文件路径：去两端引号与空白（兼容拖拽进终端的带引号路径） */
function cleanPath(raw) {
  return String(raw || '').trim().replace(/^["']|["']$/g, '');
}

/**
 * 整段文本按行解析为有效公钥列表 + 无效行（跳过空行/注释行，UTF-8 BOM 兼容）。
 * @returns {{keys:Array<{line:string,fingerprint:string,algo:string,comment:string}>, invalidLines:string[]}}
 */
function parseKeysText(text) {
  const keys = [];
  const invalidLines = [];
  String(text || '').replace(/^\uFEFF/, '').split(/\r?\n/).forEach((raw) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    if (keymgr.isValidPubLine(line)) {
      keys.push({
        line,
        fingerprint: keymgr.fingerprint(line),
        algo: keymgr.algoName(line),
        comment: keymgr.keyComment(line),
      });
    } else {
      invalidLines.push(line.slice(0, 60));
    }
  });
  return { keys, invalidLines };
}

/** 读取公钥文件并解析（路径经 cleanPath 清理），失败抛出原样 fs 错误 */
function readKeysFile(raw) {
  const p = cleanPath(raw);
  const text = fs.readFileSync(p, 'utf8');
  return { path: p, ...parseKeysText(text) };
}

/**
 * 给公钥行追加/替换 #imported:<label> 注释：
 * - 注释 token 含 #imported: 或 #issued: 标记时原地改写为 #imported:<label>（保留来源主机前缀，
 *   如 `Aidee@DESKTOP-OFFICE#issued:pura70` → `Aidee@DESKTOP-OFFICE#imported:pura70`，导入 key
 *   归〔外部导入〕类）；首个标记 token 改写后不再重复追加，异常的后续标记 token 直接丢弃；
 * - stripToken：可选，需从注释中移除的原标签 token（末尾启发式识别场景避免重复，如
 *   `alis@DESKTOP-A phone` → `alis@DESKTOP-A #imported:phone`）；标记 token 优先于 strip 处理；
 * - label 为空或清洗后为空时原样返回（保留原注释）。
 */
function attachImportedLabel(line, label, stripToken) {
  const clean = issue.sanitizeLabel(label);
  if (!clean) return String(line || '').trim();
  const parts = String(line || '').trim().split(/\s+/);
  const base = parts.slice(0, 2);
  const strip = stripToken != null ? String(stripToken).trim() : '';
  let replaced = false;
  const rest = [];
  for (const t of parts.slice(2)) {
    if (IMPORTED_RE.test(t) || issue.ISSUED_RE.test(t)) {
      if (!replaced) {
        rest.push(t.replace(issue.ISSUED_RE, `#imported:${clean}`).replace(IMPORTED_RE, `#imported:${clean}`));
        replaced = true;
      }
      continue;
    }
    if (strip && t === strip) continue;
    rest.push(t);
  }
  if (!replaced) rest.push(`#imported:${clean}`);
  return [...base, ...rest].join(' ');
}

/**
 * 自动识别公钥注释中已有的标签（三级优先）：
 * 1. #imported:<标签> 显式标记（重导入幂等）；
 * 2. #issued:<标签> 颁发标记：外部机器颁发给某设备的 key，导入后标签沿用设备名（扫描全部 token）；
 * 3. 注释末尾单 token 启发式：不含 @（排除常规 user@host 注释）、允许 # 前缀（如 #pad → pad），
 *    经 sanitizeLabel 清洗非空即认定为标签。
 * 识别不到返回 null。
 */
function detectTag(comment) {
  const viaMarker = importedLabelOf(comment);
  if (viaMarker) return viaMarker;
  const issued = issue.ISSUED_RE.exec(String(comment || ''));
  if (issued) return issue.sanitizeLabel(issued[1]) || null;
  const tokens = String(comment || '').trim().split(/\s+/).filter(Boolean);
  const last = tokens.length ? tokens[tokens.length - 1] : '';
  if (!last || last.includes('@') || last.includes('#issued:')) return null;
  return issue.sanitizeLabel(last.replace(/^#/, '')) || null;
}

module.exports = {
  IMPORTED_RE,
  importedLabelOf,
  cleanPath,
  parseKeysText,
  readKeysFile,
  attachImportedLabel,
  detectTag,
};
