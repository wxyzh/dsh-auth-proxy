# AGENTS.md — dsh-auth-proxy

dsh Web GUI 的令牌鉴权反向代理插件：宿主侧在 `0.0.0.0:<port>` 独占网络面，内置登录页校验静态令牌后，
把 HTTP + WebSocket 转发到回环 dsh webserver（默认 `127.0.0.1:3080`）；浏览器侧在「设置 > 插件配置」
渲染配置卡片。主仓（DSH 源码 checkout）**零改动**：webserver 保持在 127.0.0.1，本插件持有对外 socket。

## 仓库规则

- **禁止修改 DSH 源码**：对官方 checkout 零写入，挂载只走 `cordis.patch.yml` + profile 机制
  （`dsh plugin --profile web add link:<abs path>/dsh-auth-proxy`）。
- **基于官方 NPM SDK 开发**：类型与运行面来自 `@deepseek-ai/*` peer/devDependencies（node_modules 解析）；
  禁止 tsconfig `extends` / `paths` / `references` 指向任何 DSH 源码 checkout。
- **命名**：包名沿用 `dsh-` 前缀（`@ken/dsh-auth-proxy`，私有 scope，非官方 `@deepseek-ai`）；
  发布到 npm 前需维护者确认版本号与 scope，避免误发。
- **禁止 emoji**：代码、注释、文档、UI 文案、提交信息均不得出现 emoji 字符；需要装饰符号时用普通字符
  （如 `-`、`*`）或去掉。
- **构建**：npm 工作流（非 pnpm）。`npm run build` = `tsc -p tsconfig.json`（宿主侧出 `lib/types/`）+
  `tsdown`（浏览器侧出 `lib/client.js`，closure-factory 产物，经 `window.__ModuleLoader__.load` 加载）。
  发布产物白名单见 `package.json#files`（`lib/**/*.js`、`*.d.ts`、`*.d.ts.map`、`cordis.patch.yml`），
  **新增源码文件必须落在 `src/` 下且被构建覆盖**：宿主侧 `src/index.ts`，浏览器侧 `src/client/`。
- `ws` 依赖当前未被源码引用，属清理项，勿新增对它的使用。

## 架构与安全不变式（改动前必读）

- **代理即网络边缘**：`clientIp()`（`src/index.ts`）**不得信任 `X-Forwarded-For`**（无可信上游，信任即白名单/锁定绕过）；
  转发（`forward` / `doUpgrade`）前剥离 `x-forwarded-for`、`x-real-ip`。
- **令牌**：`tokenConfigured()` 判定空串或占位符 `change-me` 为未配置，此时 `sync()` 禁用代理、绝不监听；
  登录比对必须走 `safeEqual()`（SHA-256 + `timingSafeEqual`）；schema 中 token 带 `role('secret')`，
  `GET /api/dsh-auth-proxy/config` 永不回传令牌值，只回 `tokenSet` 布尔。
- **会话**：cookie `HttpOnly; SameSite=Lax; Path=/`；会话与失败计数在内存，重启即失（设计如此）。
- **配置分层（勿改回）**：解析 = `base` 层（dsh-settings scope，无 settings 服务时退化为组合入口）+ 用户文件
  `~/.dsh/dsh-auth-proxy.json`（文件层**权威**）。卡片 PUT 只写文件、只更新 `fileConfig`，**不得重指 `current`**；
  `installSettingsSection` 的 `setSource` 只换 `base` 层。文件层是唯一持久存储，重启生效。
- **`sync()` 两态**：仅 `host`/`port`/监听状态变化才重建服务器（`teardownServer` 优雅关闭：
  `close()` + 1.5s 兜底强关）；其余字段（token、banner、TTL、白名单、锁定）热更新，只换 `live` 快照。
  PUT 处理器**先写响应再 `setImmediate(sync)`**，保证保存响应先于重建到达浏览器。
- **请求处理器一律读 `live` 快照**（每请求 `const c = live`），禁止闭包捕获 `sync()` 时的 cfg 快照。

## 客户端纪律

- `@deepseek-ai/*` 只能 **type-only** 导入（`import type {}`）；值导入只允许平台种子（react 等），
  跨插件协作走 cordis 服务（`ctx.slots` / `ctx.locale`）。
- 文案 zh/en 双语：key 注册在 `src/client/locales.ts` 的 `AuthProxyKey` 联合类型，**新增 key 必须两语齐全**。
- 卡片走插件自有 `/api/dsh-auth-proxy/config`（dsh-settings 客户端暴露白名单对第三方封闭，勿改走 settings scope）。

## 已知边界（勿当 bug 误修）

- IP 白名单仅 IPv4（IPv6 字面量如 `::1` 不匹配 IPv4 CIDR）。
- 无 TLS：令牌经明文 HTTP 传输，局域网内可嗅探——这是为局域网 HTTP 可用性（UUID polyfill）做的取舍。
- 会话/失败计数 Map 无主动清理，长期运行缓慢增长（可接受）。
- 当前目录尚未初始化 git 仓库；改动前先确认状态，`lib/` 是构建产物。

## 提交前检查

```sh
npm run typecheck
npm run build
npm run smoke
```

`npm run smoke` 驱动构建产物（`scripts/smoke.mjs`，stub cordis ctx + 临时 `DSH_HOME` 隔离真实用户配置），
覆盖：空/占位令牌不监听、登录流程、XFF 伪造不绕过白名单、PUT 热更新不重建、PUT 改端口重建、PUT 占位令牌禁用。
