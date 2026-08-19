# dsh-auth-proxy

DSH Web GUI 的令牌鉴权反向代理插件：在 dsh web 前面加一道静态令牌登录墙。宿主侧在
`127.0.0.1:<port>`（默认 8443）监听，未认证访问显示内置登录页，校验令牌后签发 HttpOnly
会话 cookie，再把 HTTP 与 WebSocket 流量转发给回环 dsh webserver。**零 DSH 源码改动**：
webserver 保持监听 `127.0.0.1:3080`，本插件持有对外 socket。

```
browser ──► auth proxy :8443 (127.0.0.1) ──► dsh webserver 127.0.0.1:3080
                ├─ 未认证 → 内置登录页
                ├─ POST 令牌 → HttpOnly 会话 cookie
                └─ 已认证 → 转发 HTTP + WebSocket
```

## 功能

- 内置登录页（POST `/__dsh_auth/login` 校验令牌），登出走 POST `/__dsh_auth/logout`。
- 令牌比对使用 SHA-256 + `timingSafeEqual`，避免时序侧信道。
- 会话 cookie：`HttpOnly; SameSite=Lax; Path=/`，**永久有效**（Max-Age 10 年）且**无状态**：
  值为 `payload.signature`（HMAC-SHA256，密钥由令牌派生），服务端不存会话，**重启后 cookie 依然有效**；
  **更换令牌会使所有已登录会话立即失效**（全体下线），登出仅清除客户端 cookie。
- IP 白名单（支持 CIDR，IPv4）可整体绕过令牌；失败登录锁定（按 IP，阈值与时长可配）。
- 配置实时可改：设置页注册成一个独立的 `settings.section` 分区（与 Models/General 同级，
  非插件列表内的折叠卡片），经 `ctx.settingsScope` 读写 `dsh-auth-proxy` 命名空间——收 revision 栅栏、
  由 Host 的 settings `validate` 校验并持久化，非自建 HTTP 写接口；对纯 HTTP 局域网地址自动注入
  `crypto.randomUUID` polyfill，保证前端 RPC 可用。
- 局域网地址可正常编辑 web-ui 设置（主题、语言、插件配置等）：dsh web 客户端按页面源判定回环，
  非回环来源会把设置面降级为只读；代理转发 HTML 时注入 loopback-compat 脚本，把
  `connection.isLoopback` 打开——与代理把 Host/Origin 改回回环后服务端按回环放行的事实一致，
  鉴权仍由本插件令牌墙把关。
- 状态可视：宿主终端直接打印 `dsh-auth-proxy: listening on http://<host>:<port>`（console.log 镜像，
  dsh web 不把插件 `ctx.logger` 打到终端），设置卡片同样显示实际监听地址；通过 `accessUrls` 声明的
  入口地址（可含 HTTPS 域名）会展示在卡片与登录页，多域名场景一眼可知该用哪个 URL。
- **无 TLS，禁绑通配/公网**：监听地址仅允许回环与内网（默认 `127.0.0.1`）；`0.0.0.0`、`::` 与公网 IP
  在保存与启动时都会被拒绝。外部访问请在前面挂 TLS 反向代理，回指本监听地址。

## 安装与卸载

`dsh plugin` 把参数转发给 pnpm，在 profile 目录安装依赖，并按 `dsh.bundle` 声明自动把插件
挂进 web profile roster（即 `cordis.patch.yml` 的 `auth-proxy` 行），无需额外激活步骤。

安装（npm 发布版与 GitHub 直装二选一）：

```sh
# npm 发布版
dsh plugin --profile web add @wxyzh/dsh-auth-proxy

# 或 GitHub 直装（固定 tag 版本）
dsh plugin --profile web add github:wxyzh/dsh-auth-proxy#v0.1.0
```

本地开发用 link 方式（无需发布，直接挂源码目录）：

```sh
dsh plugin --profile web add link:<abs 路径>/dsh-auth-proxy
```

卸载（无论以哪种方式安装，都用包名）：

```sh
dsh plugin --profile web remove @wxyzh/dsh-auth-proxy
```

说明：`dsh plugin` 需要 pnpm 在 PATH 上；GitHub 直装时若 pnpm 拦截 `prepare` 构建脚本，
按 CLI 提示在 profile 的 `pnpm-workspace.yaml` 添加 `allowBuilds` 键后重试。本插件是宿主 +
浏览器双半插件：宿主侧 `src/index.ts`，浏览器侧 `src/client/`（设置卡片）。

## 配置

组合入口配置（`cordis.patch.yml`）：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `host` | `127.0.0.1` | 监听地址（仅回环与内网；无 TLS，禁止 `0.0.0.0`/`::`/公网 IP） |
| `port` | `8443` | 对外监听端口 |
| `targetHost` | `127.0.0.1` | 回环转发目标 |
| `targetPort` | `3080` | 回环转发端口 |
| `token` | 见下 | 共享访问令牌 |
| `banner` | `''` | 登录页横幅文案 |
| `allowedIps` | `[]` | IP 白名单（如 `["127.0.0.1", "10.0.0.0/8"]`），空 = 一律要令牌 |
| `accessUrls` | `[]` | 对外访问地址（可含 HTTPS 域名，多域名逗号分隔），仅用于展示 |
| `maxFailures` | `0` | 失败锁定阈值（0 = 关闭锁定） |
| `lockoutMinutes` | `15` | 锁定时长（分钟） |

**令牌**：推荐用环境变量引用，不要把字面量写进配置：

```yaml
token: !!js process.env.DSH_AUTH_TOKEN
```

安全默认：令牌为空或仍是占位符 `change-me` 时，**代理保持禁用、绝不监听**——只有配了真实令牌才会开放端口。

**配置分层（改动前先读 `AGENTS.md`）**：**dsh-settings scope 是唯一写入路径**——Host 用
`installSettingsSection` 注册 `dsh-auth-proxy` 命名空间（`base` = 组合入口，用户文档层由部署的
settings provider（如 `dsh-settings-file`）持久化，无 settings 服务时退化为组合入口）；设置分区经
`ctx.settingsScope` 读写，revision 栅栏 + Host `validate` 把关，监听 host 策略在 `validate` 钩子拒绝。
**不存在自建的卡片配置文件**（旧的 `~/.dsh/dsh-auth-proxy.json` 权威已废弃）。令牌占位符是合法存储值，
代理保持禁用。运行态只读探测走 `GET /api/dsh-auth-proxy/status`（listening / tokenSet / accessUrls），
永不回传令牌值，只回 `tokenSet` 布尔。

## 安全说明

- 代理即网络边缘：**不信任 `X-Forwarded-For`**（客户端可伪造，信任即白名单/锁定绕过），
  转发前剥离 `x-forwarded-for` / `x-real-ip`。
- **监听地址策略**：无 TLS 意味着绑到通配（`0.0.0.0`/`::`）或公网 IP 会把明文令牌暴露到网络，
  因此默认 `127.0.0.1`，且仅接受回环与内网地址（`127/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、
  `::1`）；保存时由 settings `validate` 钩子拒绝、启动时由 `sync()` 拒绝，双重把关，日志与卡片会给出原因。外部访问请用 TLS 反向代理
  （nginx/Caddy 等）终止加密后回指 `127.0.0.1:8443`，`accessUrls` 里填对外域名。
- 无 TLS：即使仅内网监听，令牌仍经明文 HTTP 传输，同网段可嗅探。这是为局域网 HTTP 可用性做的取舍；
  需要加密传输时请在前方套 TLS 终结。
- 会话为**无状态签名 cookie**（HMAC 密钥派生自令牌，重启不失效）；**无单点剔除能力**——更换令牌即全体下线，
  登出仅清客户端 cookie；失败计数由定时清理兜底（每 30 分钟扫描，闲置超 1 小时的记录清除）。锁定为按 IP，IPv6 字面量（如 `::1`）不匹配 IPv4 白名单。

## 开发

- 构建：`npm run build`（`tsc` 出宿主侧 `lib/types/` + `tsdown` 出浏览器侧 `lib/client.js`）。
- 类型检查：`npm run typecheck`。
- 冒烟测试：`npm run smoke`（驱动构建产物，覆盖空/占位令牌不监听、登录流程、XFF 伪造不绕过白名单、
  热更新不重建、改端口重建、占位令牌禁用、拒绝公网监听地址、HTML 双脚本注入、无状态会话重启存活与换令牌全体下线）。
- 仓库规则与安全不变式见 `AGENTS.md`；许可见 `LICENSE`（MIT）。

## 已知限制

- 会话永久有效且无状态（签名 cookie，重启不失效）；**无单点剔除**，改令牌即全体下线、登出仅清 cookie，属预期；失败计数表由定时清理兜底。
- 当前目录已是 git 仓库（初始提交已建）。