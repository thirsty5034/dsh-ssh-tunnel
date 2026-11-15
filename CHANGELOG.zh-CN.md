# 更新日志

[English](./CHANGELOG.md) | [简体中文](./CHANGELOG.zh-CN.md)

## 0.5.1 — 2026-11-15

### 修复
- **终端输出不再撕裂多字节字符（H1）。** ssh2 channel 分包不保证 UTF-8 边界，按块独立解码会把跨包字符永久变成 U+FFFD。终端环形缓冲（`pushOutput`）与 `SSHManager.exec` 均改为 `StringDecoder` 增量解码。
- **环形缓冲淘汰不再吞掉未读输出（H2）。** 淘汰预算改为按 UTF-16 码元计数——与客户端游标同一单位——而非 `Buffer.byteLength`。大块多字节输出（如 600KB 中文）不再被字节预算提前淘汰，且淘汰边界始终与客户端已读位置对齐。
- **`exec` 的 `max_bytes` 恢复字节语义（M1）。** 旧实现按 UTF-16 下标切片，中文可超限 3 倍、emoji 4 倍；现在在字节数组上按码点边界截断，并在截断发生时返回 `truncated: true`。
- **迁移后的 draft 明文文件被删除（M2）。** 一次性迁移把明文密码/口令/PEM 拷入 `secrets.json` 后，旧 draft JSON 仍留在磁盘上；现在迁移标记落盘后即删除。
- **并发打开 shell 只开一条 PTY（M3）。** 并发的 `shellOpen`/`read_session` 此前会各自调用 `client.shell()`，失败者成为孤儿流持续制造重复输出；现在按会话串行化。
- **建连完成后复核授权（M4）。** SSH 握手期间授权被撤销时，不再留下一条指向未授权主机的活动连接；客户端立即关闭。
- **trusted-host 层识别端口（S1）。** 降级围栏中，同域名不同端口的 `Origin` 现在被拒绝；配置项支持 `host`、`host:port` 或 URL 形式。
- **空 `projectPathKey` 失败关闭（L3）**：结果门禁不再跳过撤销检查。
- **`shellResize` 钳制 pty 尺寸（L4）** 到 ssh2 uint32 范围（1..4294967295），HTTP API 与 SSHManager action 均生效。
- **`exec` 的 `cwd` 先 trim（L6)**，`"/workspace "` 不再静默丢失 `cd`。
- **Host-key 提示过期（L1）**：10 分钟后自动清理，待处理映射上限 64 条；被遗弃的提示不再无限堆积。
- **Vendor 资源每小时重新验证（L2）**，替代 `max-age=31536000, immutable`，插件升级后 xterm 产物能真正更新。

### 新增
- **宿主兼容性元数据。** 现在声明 `dsh.manifestVersion: 1` 与 `engines.dsh: ">=0.2.1-rc.1"`（对应 0.2.x 线的 connection 服务要求）；`react`/`react-dom` 声明为可选 peer（客户端渲染依赖宿主 React）。
- **`scripts/smoke-test.mjs` 随包发布**，npm/tarball 安装后 `npm test` / `npm run check` 可用（回应上游「安装包缺冒烟脚本」的 issue）。

## 0.5.0 — 2026-11-15

### 新增
- **API 信任三级降级链。** 请求围栏在 DSH `connection` 服务未挂载时不再整体 403：`connection.requestRejection`（权威）→ `webStartup.trustedHosts`（自管 `--trusted-host` 列表）→ 仅回环放行。没有 Connection 服务的部署形态也能保住带围栏的 API。当前 DSH 0.2.x web 部署下行为不变（Connection 仍是权威）。

### 修复
- **SFTP/终端浮层让出桌面顶栏。** 全屏浮层改用 `inset: var(--dsh-frame-chrome-top, 0px) 0 0 0`，桌面端的原生窗口按钮不再被盖住（web 部署没有该变量，视觉零变化）。
- **游标单位钉死为宿主字符串下标。** 轮询 tick 直接采用 `r.length`，不再用 `chunk.length` 自行推导；首屏 drain 在 ring 淘汰导致 buffer 变短时重新锚定到保留前缀——多字节输出不会再造成游标错位。

## 0.4.7 — 2026-11-15

### 修复
- **在 DSH 0.2 上重新挂载路由。** `inject` 仍依赖已删除的 `webRuntime`，插件一直 pending，`/dsh-ssh-tunnel/*` 落到静态文件兜底（空 body 的 HTTP 405）。准入改走 `ctx.connection.requestRejection`（仅 `undefined` 放行），JSON API 与 vendor 资源路由都走同一道围栏。需要 DSH **0.2.1-rc.1+** 与 `dsh-better-sidebar` v0.28。不保留 `webRuntime` 兼容层。
- **修复终端轮询导致输出重复（issue #11）。** 120ms 的 shell 轮询定时器可能在上一次 `shellRead` 尚未返回时再次触发；两次请求携带同一个 `since` 游标、返回同一段内容，终端就会写出 `abcabc`。现在在途请求未结束前跳过本次 tick，且每次 `await` 后都复查终端是否已取消/销毁；瞬时 API 错误也不会让在途标志卡死。
- **修复终端首屏输出丢失。** 原先启动时只做一次 `shellRead(since: 0, full: true)` 快照，请求在途期间主机继续追加的输出会被丢掉（欢迎横幅/首个提示符被截断）。现在启动阶段按会话实时游标增量追赶（有上限的循环），追平后再交给轮询。

## 0.4.6 — 2026-09-15

### 修复
- **终端不再报「无法加载 xterm」。** `require("@xterm/xterm")` 在 DSH 浏览器模块表里永远解析不到（只回答平台种子与已注册插件 row），而 0.4.4 移除 jsDelivr 回退后没有可用路径。插件现把 `@xterm/xterm@5.5.0` 与 `@xterm/addon-fit@0.11.0` 钉为运行时依赖，并将其 UMD/CSS 从同源白名单路由（`/dsh-ssh-tunnel/vendor/*`）下发；客户端用普通 `<script>`/`<link>` 标签加载，原来的模块表 require 路径仅作降级保留。永不访问第三方 CDN。

### 安全
- **Vendor 路由白名单化。** `/dsh-ssh-tunnel/vendor/*` 只解析三个固定资源名；其它任何请求（含路径穿越）一律 404，且不会触碰文件系统。

## 0.4.5 — 2026-09-09

### 移除
- **不再提供键盘交互登录。** 只能在堡垒机网页/客户端里用的主机无法绑定到本插件。侧栏认证方式只保留密码与私钥。已保存的 `keyboardInteractive` 主机记录仍留在磁盘，但连接、存成 KBI、重连和 `SSHManager` 都会失败，并提示改为密码或私钥（`credential=unsupported`）。

## 0.4.4 — 2026-09-09

### 安全
- **本地路径在解析符号链接后仍必须落在 `/workspace`。** 上传/下载/列举/建目录/删除/重命名会同时拒绝词法逃逸和指向工作区外的符号链接。删除符号链接只 unlink 链接本身，不跟随目标递归。
- **HTTP 会话 API 必须带 `projectPathKey`。** 省略该字段不再跳过项目检查。跨站 `Origin` 会被拒绝；`0.0.0.0` 不再当作回环。
- **损坏的 `secrets.json` 失败关闭。** 解析失败不再当成空库被下一次 `saveHost` 写回。JSON 采用临时文件 + rename 原子写入。
- **旧稿迁移幂等。** 标记文件 + host+port+username 去重，避免每次启动复制主机。
- **结果门禁覆盖写操作与 HTTP。** 写文件/上传/mkdir/重命名/删除/`send_input` 以及对应侧栏 API 在回报成功前复检授权。缺少授权谓词会抛错，不再静默放行。
- **拒绝键盘交互空应答。** 侧栏在没有应答 UI 时不会拨号；KBI 意外断开立即墓碑，不再空转重连。
- **xterm 仅使用打包模块。** 去掉 jsDelivr CSS/JS 回退。

### 修复
- 重连与 `close` 竞态时会 `end()` 新客户端，不再挂到已删除记录上。
- `openSftp` 与 `ensureShell` 遵守与 exec 相同的超时/取消合同。

## 0.4.3 — 2026-09-08

### 安全
- **在飞操作的结果门禁**。若 `SSHManager` 操作（exec / read_session / sftp_list / sftp_stat / sftp_read_text / sftp_download）执行期间该主机的项目授权被撤销，结果在交付前会复检：来自已撤销主机的输出被丢弃，调用以 `not authorized` 失败。
- **撤销授权后 `sftp_download` 不留任何本地文件**。若传输期间或之后授权被撤销，已写入的本地文件会被删除（含中途失败的部分写入），并拒绝交付结果。

### 修复
- **终端面板不再静默轮询已死会话**。会话被关闭或主机授权在终端打开期间被撤销时，客户端停止轮询并显示「会话已断开」，而不再每 120ms 无反馈地空转请求。

## 0.4.2 — 2026-09-08

### 安全
- **撤销某主机的项目授权后，已建立的隧道会话立即失效。** 此前只有新建连接和 `SSHManager` 工具会复检授权；已打开会话上的 shell / SFTP 操作、以及重连（含自动重连）在撤销授权后仍然可用。现在每次会话使用都会按该会话所属项目的授权重新校验（`requireLiveSession`），重连 / 自动重连拒绝复活已撤销主机，`setGrants` 与删除主机时还会主动关闭受影响的存活会话。

## 0.4.1 — 2026-09-08

### 修复
- 从 `dsh.client.inject` 移除 **`@deepseek-ai/dsh-client-runtime`**。该包在 DSH 0.1.2 已删除（社区升级卡 `DSH-0.1.2-A1-25`）；保留该幻影依赖可能让 client 装配行在 0.1.2 宿主上 pending。保留 `@deepseek-ai/dsh-client-locale`（提供 `ctx.locale`）。

## 0.4.0 — 2026-09-01

### 新增
- 会话断开后保留**墓碑**（重连 + 关闭），无 TTL。意外断开自动重连最多 3 次，同一 `session_id`。
- ssh2 **keepalive** 30s × 3，半开连接会变成真正断开，而不再假活。
- `SSHManager` 支持 `timeout_ms`（1s–300s），覆盖 exec / SFTP / shell。默认：exec 与 SFTP 元数据 30s，SFTP 传输 120s；整次调用天花板 300s。Stop / `exec.signal` 会中止并关掉 channel。

### 变更
- `reuse_or_create` **复活**同主机最老墓碑，不再另开一条活会话。重连失败则保持断线并让这次工具失败。
- 显式已断开的 `session_id` 立即失败（不再卡在 ssh2 上）。重连中的 id 会等到活过来。
- 键盘交互主机不能原地重连，需关闭后在 UI 重新 Connect。

## 0.3.11 — 2026-08-26

### 修复
- **适配 dsh-better-sidebar ≥ 0.16**：终端 / SFTP 中央面板重新全屏居中。0.16.x 给侧栏面板容器加了 `contain: layout`（并引入统一面板宿主 / 自由窗口），按 CSS Containment 规范该容器成为**后代 `position:fixed` 元素的包含块**——此前内联渲染的全屏覆盖层因此被「关进」右侧窄条。现改为通过 React portal 挂载到 `document.body`，不再依赖任何祖先的定位假设（右键菜单、对话框随覆盖层一起迁移）；react-dom 缺失时回退旧内联渲染。

## 0.3.10 — 2026-08-18

### 修复
- 主机库 / 隧道列表：过长 endpoint（如 IPv6）不再把 **编辑/删除** 等按钮挤出可视区——文案可换行，操作区始终保留

## 0.3.9 — 2026-08-18

### 修复
- **SSHManager 作为全局模型工具正确注册**（不再依赖 out-of-tree 解析 `@deepseek-ai/dsh-tools` 的 `defineTool`；改用与 modlens 相同的裸 JSON Schema 定义）。此前标准对话工具列表中看不到该工具。

## 0.3.8 — 2026-08-18

### 修复
- Host key 固定：使用 ssh2 `hostHash: sha256` 并以 hex 摘要入库（旧版 `String(Buffer)` 条目作废并重新提示信任）
- 信任 UI 展示 SHA256 指纹；`health.version` 与 `package.json` 对齐
- **Connect 不再静默写入项目授权**；须先在「项目授权」勾选主机

## 0.3.7 — 2026-08-18

### 文档
- README（中/英）：明确 **致谢 / 参考来源** — 产品形态参考开源 [LiveAgent](https://github.com/thirsty5034/LiveAgent)；DSH 原生实现，非 fork  

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
