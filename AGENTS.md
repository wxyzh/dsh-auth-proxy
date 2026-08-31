# AGENTS.md — dsh-auth-proxy

dsh Web GUI 的令牌鉴权反向代理插件：宿主侧在 `127.0.0.1:<port>`（默认）监听，内置登录页校验静态令牌后，
把 HTTP + WebSocket 转发到回环 dsh webserver（默认 `127.0.0.1:3080`）；浏览器侧在「设置」渲染一个独立的
auth-proxy 配置分区（`settings.section`，与 Models/General 同级，非插件列表内的折叠卡片）。主仓（DSH 源码 checkout）**零改动**：webserver 保持在 127.0.0.1，本插件持有对外 socket。

## 仓库规则

- **禁止修改 DSH 源码**：对官方 checkout 零写入，挂载只走 `cordis.patch.yml` + profile 机制
  （`dsh plugin --profile web add link:<abs path>/dsh-auth-proxy`）。
- **基于官方 NPM SDK 开发**：类型与运行面来自 `@deepseek-ai/*` peer/devDependencies（node_modules 解析）；
  禁止 tsconfig `extends` / `paths` / `references` 指向任何 DSH 源码 checkout。
- **命名**：包名沿用 `dsh-` 前缀（`@wxyzh/dsh-auth-proxy`，私有 scope，非官方 `@deepseek-ai`）；
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
  只读 `GET /api/dsh-auth-proxy/status` 永不回传令牌值，只回 `tokenSet` 布尔。
- **会话**：cookie `HttpOnly; SameSite=Lax; Path=/`，**永久有效**（Max-Age 10 年）且**无状态**：
  值为 `payload.signature`（HMAC-SHA256，密钥由令牌 `hash(token)` 派生，见 `src/index.ts` 的 `issueSession`/`isValidSession`），
  服务端不存会话表，**重启后 cookie 仍有效**；**更换令牌 = 全体下线**（密钥变化令全部旧签名失效），登出仅清客户端 cookie；
  失败计数由定时清理兜底（30 分钟扫描，闲置超 1 小时清除）。
- **配置写入（与官方一致）**：dsh-settings scope 是**唯一写入路径**——Host 用 `installSettingsSection` 注册
  `dsh-auth-proxy` 命名空间（`base` = 组合入口，用户文档层由部署的 settings provider（如 `dsh-settings-file`）持久化，
  无 settings 服务时退化为组合入口）；浏览器配置分区经 `ctx.settingsScope` 读写（revision 栅栏，Host `validate` 把关）。
  **不存在自建的卡片配置文件**（旧的 `~/.dsh/dsh-auth-proxy.json` 权威已废弃）。监听 host 策略在
  `installSettingsSection` 的 `validate` 钩子拒绝；令牌占位符是合法存储值，代理保持禁用。
- **监听地址（勿放开）**：无 TLS，`listenHostIssue()`（`src/index.ts`）只允许回环与内网地址
  （`127/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`::1`，`localhost`），
  **拒绝 `0.0.0.0`、`::` 与公网 IP**——默认 `127.0.0.1`，外部访问须用 TLS 反向代理回指监听地址。
  settings `validate` 钩子与 `sync()` 双重拒绝，禁止放宽。
- **`sync()` 两态**：仅 `host`/`port`/监听状态变化才重建服务器（`teardownServer` 优雅关闭：
  `close()` + 1.5s 兜底强关）；其余字段（token、banner、accessUrls、白名单、锁定）热更新，只换 `live` 快照。
  写路径走 dsh-settings scope，重建由 settings 的 `onChange`/watcher 驱动（非自建 HTTP PUT）。
- **终端可见状态行**：dsh web 不把插件 `ctx.logger` 输出路由到终端（它自己的 URL 行用裸 `console.log`），
  因此监听/禁用等操作者必须看到的状态用 `say()` / `sayWarn()`（`src/index.ts`：`ctx.logger` + `console.log`
  双写镜像）输出，格式前缀 `dsh-auth-proxy: `；禁止把请求级日志（debug 等）改成 console.log 刷屏。
- **请求处理器一律读 `live` 快照**（每请求 `const c = live`），禁止闭包捕获 `sync()` 时的 cfg 快照。
- **浏览器侧信任镜像（勿移除）**：HTML 注入除 `crypto.randomUUID` polyfill 外还有
  回环兼容 shim（`loopbackCompatScript(trustedOrigins)`，`src/index.ts`，旧名 `LOOPBACK_COMPAT_SCRIPT`
  保留为无条件版导出）——dsh web 客户端按页面源判定回环，非回环来源把设置面降级为只读；而代理把
  Host/Origin 改回回环后服务端本就把代理流量当回环放行（含 privileged settings/credentials 方法）。
  鉴权仍由本插件令牌墙把关，脚本不新增攻击面。
- **回环 shim = 种子 transport（2026-08-31 定稿，alpha.2 实发）**：`@deepseek-ai/dsh-client-connection`
  的 `connection.isLoopback` 判定首项为 `transport?.ownsHost === true`（lib/client.js:4729），而
  `globalThis.__DSH_TRANSPORT__` 在 dsh web 全库只读、从未被赋值（combo + web shell 赋值点均为 0，
  读方全走可选链）。shim 只需 `Object.assign({}, prev, { ownsHost: true })` 种子该全局，isLoopback 即
  恒 true；web shell 读 `o?.loadBundle`、connection 读 `transport?.fetch/openStream` 均得 undefined，
  与无 shim 时**零行为差异**。冒烟用例 8b 校验：命中白名单才种子 / 未命中不种子 / 空白名单无条件。
- **关键坑：禁止 patch `ctx.provide`，也禁止 wrap `__ModuleLoader__`（曾致白屏）**：曾把 connection
  apply 拿到的全局 root ctx 的 `ctx.provide` 永久替换且不还原——cordis 后续依赖 `ctx.provide` 注册
  `slots` 等服务，被替换后 `ctx.slots.renderSlot('root')` 报 `cannot get property "slots" without inject`
  （combo 29580 处）→ 8443/https 白屏。wrap `__ModuleLoader__` 的 load/create 也因 alpha.2 反复
  `create()` 换 live loader 而静默失效。**最终方案完全不触碰模块系统，只种子 transport**。若未来改回
  模块系统手术，必须保留 `__dshLoopbackWrapped__` 幂等标记与看门狗（旧实现留档于
  `src/index.ts.bak-loopbackA-20260831-212415`），并重跑冒烟 8b。
- **入口白名单（trustedOrigins = accessUrls）**：`decorateHtml` 第 4 参接收 `live.accessUrls`，非空时
  shim 只在页面 origin/host 命中列表（origin 或 host/hostname 匹配，容忍带/不带 scheme）才强制 loopback，
  其余经代理的来源保持远程只读（保留"远程只读/本机可写"粒度）；空列表 = 无条件（历史行为，向后兼容）。
  `accessUrls` 语义由"仅展示"升级为"展示 + 回环白名单"，改语义时勿连设置卡片与 locales 提示一起处理。

## 客户端纪律

- `@deepseek-ai/*` 只能 **type-only** 导入（`import type {}`）；值导入只允许平台种子（react 等），
  跨插件协作走 cordis 服务（`ctx.slots` / `ctx.locale`）。
- 文案 zh/en 双语：key 注册在 `src/client/locales.ts` 的 `AuthProxyKey` 联合类型，**新增 key 必须两语齐全**。
- 浏览器配置页经 `ctx.settingsScope` 读写 `dsh-auth-proxy` 命名空间，注册成一个 `settings.section` 独立设置分区
  （`id: 'dsh-auth-proxy'`，经 `ctx.slots.inject('settings.section', …)` 延迟到声明落地后再注册；导航 `label` 用
  **thunk**（`() => t('title')`），命名空间的 nav 缓存按 locale revision 重算并逐次重读 thunk，故无需 `locale/change`
  重注册）；不使用 `settings.plugin.item` 折叠卡片。仅 `GET /api/dsh-auth-proxy/status` 作只读运行态探测
  （listening / tokenSet / accessUrls），不做任何写。

## 已知边界（勿当 bug 误修）

- IP 白名单仅 IPv4（IPv6 字面量如 `::1` 不匹配 IPv4 CIDR）。
- 无 TLS：令牌经明文 HTTP 传输，同网段可嗅探——这是为局域网 HTTP 可用性（UUID polyfill）做的取舍；
  监听地址已限制为回环/内网（见上），禁止放宽。
- 会话**永久有效**（cookie Max-Age 10 年）且**无状态**（HMAC 签名，密钥派生自令牌）：重启不失效；
  **无单点剔除**，改令牌即全体下线、登出仅清 cookie，属预期；失败计数表由定时清理兜底。
- 当前目录已是 git 仓库（初始提交已建）；改动前先确认状态，`lib/` 是构建产物。

## 提交前检查

```sh
npm run typecheck
npm run build
npm run smoke
```

`npm run smoke` 驱动构建产物（`scripts/smoke.mjs`，stub cordis ctx + 内存 settings provider，隔离真实用户配置），
覆盖：空/占位令牌不监听、登录流程、XFF 伪造不绕过白名单、settings 写热更新不重建、settings 写改端口重建、
settings 写占位令牌禁用、settings 校验拒绝公网监听地址、转发 HTML 双脚本注入（UUID polyfill + loopback-compat）、
无状态会话重启存活与换令牌全体下线。**alpha.2 适配后 stub 的 settings provider 已补 `installSection`**
（代理到 `register` + setSource/onChange 钩子），与宿主 `dsh-settings` 的 `installSection(owner, ns, schema, entry, hooks)`
签名一致；smoke 需在此 stub 可用的前提下跑通（当前 70 passed）。
