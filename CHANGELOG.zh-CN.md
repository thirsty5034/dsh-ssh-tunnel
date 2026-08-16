# 更新日志

[English](./CHANGELOG.md) | [简体中文](./CHANGELOG.zh-CN.md)

## 0.3.6 — 2026-08-16

### 社区发布形态
- 对齐 dsh-better-sidebar 的公开仓库结构  
- 增加 `scripts/install.sh` / `install.ps1`（默认 GitHub；`--from npm` 预留）  
- package.json：`repository` / `homepage` / `bugs` / `publishConfig`  

### 文档
- 增加简体中文 README / CHANGELOG，与英文版并列入口

## 0.3.5 — 2026-08-16

### 新增
- 客户端 i18n（对齐 dsh-better-sidebar）：`ctx.locale.register("sshTunnel", zh|en)`、`t(key)`、语言切换实时刷新

### 修复
- `zh.footerHint` 误调用 `t()` 导致插件加载 TDZ 报错

## 0.3.4 — 2026-08-16

### 变更
- 发布前规范化：包元数据、MIT LICENSE、README、CHANGELOG
- 抽取 `lib/shared/*` 纯函数与离线冒烟测试
- `shellRead` 默认只返回增量 `chunk`（`full: true` 才给全量）
- 主题 token 配色；SFTP 面板内对话框（0.3.x）

### 修复
- 主机库删除恢复确认
- 样式表缓存刷新

## 0.3.0 — 2026-08-16

- 中央终端（xterm）与双栏 SFTP
- 项目级授权、SSHManager、OpenSSH 扫描

## 0.1.0 — 2026-08-16

- 初始永久插件骨架
