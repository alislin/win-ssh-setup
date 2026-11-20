'use strict';

module.exports = {
  VERSION: '1.0.0',
  /** HTTP 配对监听端口 */
  PAIR_HTTP_PORT: 22887,
  /** UDP 发现信标端口 */
  BEACON_UDP_PORT: 22888,
  /** UDP 信标魔数，客户端据此过滤 */
  MAGIC: 'WIN-SSH-SETUP-BEACON',
  /** 临时防火墙规则名（服务器端配对端口），退出时删除 */
  TEMP_FW_RULE: 'win-ssh-setup-pair-tmp',
  /** 配对码定时轮换间隔（毫秒）：使用后立即轮换，未使用也定时轮换 */
  PAIR_CODE_ROTATE_MS: 5 * 60 * 1000,
  /** 持久配对码位数（手动激活，不轮换，异地连接用） */
  PAIR_PERSIST_CODE_DIGITS: 8,
  /** 配对码连续校验失败达到该次数后锁定 */
  PAIR_MAX_CODE_FAILS: 5,
  /** 配对码失败锁定时长（毫秒） */
  PAIR_LOCKOUT_MS: 30 * 60 * 1000,
};
