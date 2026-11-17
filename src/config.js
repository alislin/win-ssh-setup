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
};
