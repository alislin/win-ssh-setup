# win-ssh-setup

Windows SSH 免密登录一键配置工具：两台电脑各运行一次脚本，自动完成 SSH 密钥认证配置（含管理员账户 / 微软在线账户的已知问题适配），全程只需在客户端输入一个 6 位配对码。

## 快速开始

1. 两台电脑分别双击 `run.cmd`（未装 Node.js 会自动通过 winget 安装 LTS）
2. 被连接的一台选 `[1] 服务器端`（自动 UAC 提权、自动安装 OpenSSH Server），记下屏幕上的配对码
3. 发起连接的一台选 `[2] 客户端`，选择发现的服务器（或手动输 IP），输入配对码
4. 脚本自动完成：生成密钥 → 部署公钥 → 修复 ACL → 适配 sshd_config → 重启 sshd → **配置体检（无连接的 11 项检查）** → 旧 key 残留清理询问 → 可选实测验证
5. 日常管理选 `[4] 密钥管理`：区分客户端/服务端密钥，支持体检、删除、清空、备份、重新生成客户端密钥

详见 [docs/使用说明.md](docs/使用说明.md)，设计背景与手工流程见 [docs/手动操作流程.md](docs/手动操作流程.md)，技术方案见 [docs/技术方案.md](docs/技术方案.md)。

## 目录结构

```
run.cmd              双击启动器（检测/安装 Node → 运行 cli.js）
src/
  cli.js             入口与角色流程（服务器 / 客户端 / 本机自连 / 密钥管理）
  config.js          端口、魔数、版本常量
  log.js             彩色分步日志
  exec.js            子进程与外部工具封装
  env.js             环境自检（管理员、用户组、OpenSSH、本机信息）
  install.js         OpenSSH Server 安装（winget + capability 回退）与服务/防火墙善后
  elevate.js         UAC 提权重启自身
  keygen.js          ssh-keygen 封装（客户端密钥对）
  keymgr.js          密钥管理：解析/指纹/备份/删除/清空/旧 key 扫描
  audit.js           配置体检：11 项无连接配置层检查 + 一键修复
  pair-server.js     服务器端：HTTP 配对 + UDP 广播信标 + 体检回传 + 旧 key 清理接口
  pair-client.js     客户端：UDP 发现 + 配对请求 + 实时步骤/体检流 + 清理请求
  deploy.js          六步部署管线（幂等，含 sshd_config 备份/回滚）
  verify.js          ssh BatchMode 实测验证
docs/
  手动操作流程.md     原始手工流程（本工具的自动化对象）
  技术方案.md         设计决策与协议细节
  使用说明.md         用户手册
```

## 特性

- 零第三方依赖：仅使用 Node.js 内置模块
- 两机对联：公钥通过网络直接传输，无需复制粘贴
- 三层验证：部署 → 配置体检（无连接，11 项）→ 可选 BatchMode 实测
- 密钥管理：区分客户端/服务端密钥，删除/清空/备份/重新生成，全程自动备份
- 换 key 闭环：重新配对自动检测同主机旧公钥并询问清理，永不误删新 key
- 幂等：重复运行不产生重复公钥、不重复备份
- 安全：sshd_config 先备份，`sshd -t` 校验失败自动回滚；授权文件 ACL 用 SID 收紧，不受系统语言影响
