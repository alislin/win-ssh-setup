'use strict';

const { VERSION } = require('./config');

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
};

function ts() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function line(color, tag, msg) {
  console.log(`${c.dim}[${ts()}]${c.reset} ${color}[${tag}]${c.reset} ${msg}`);
}

function plain(msg) {
  console.log(msg);
}

function banner() {
  const bar = '═'.repeat(46);
  plain('');
  plain(`  ${c.cyan}${bar}${c.reset}`);
  plain(`  ${c.bold}Windows SSH 免密登录一键配置  v${VERSION}${c.reset}`);
  plain(`  ${c.cyan}${bar}${c.reset}`);
  plain('');
}

const STEP_STYLE = {
  OK: () => [c.green, 'OK  '],
  WARN: () => [c.yellow, 'WARN'],
  SKIP: () => [c.dim, 'SKIP'],
  FAIL: () => [c.red, 'FAIL'],
};

function step(s) {
  const style = STEP_STYLE[s.status] || (() => [c.cyan, '....']);
  const [color, tag] = style();
  const detail = s.detail ? `${c.dim}  — ${s.detail}${c.reset}` : '';
  line(color, tag, `${s.name}${detail}`);
}

module.exports = {
  c,
  banner,
  plain,
  step,
  info: (msg) => line(c.cyan, 'INFO', msg),
  ok: (msg) => line(c.green, 'OK  ', msg),
  warn: (msg) => line(c.yellow, 'WARN', msg),
  error: (msg) => line(c.red, 'FAIL', msg),
};
