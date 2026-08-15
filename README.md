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
- 会话 cookie：`HttpOnly; SameSite=Lax; Path=/`，**永久有效**（Max-Age 10 年）；会话存内存，重启 dsh 后所有人需重新登录。
- IP 白名单（支持 CIDR，IPv4）可整体绕过令牌；失败登录锁定（按 IP，阈值与时长可配）。
- 配置实时可改：Web UI「设置 > 插件配置」卡片（走插件自有 `/api/dsh-auth-proxy/config`），
  无需改文件；对纯 HTTP 局域网地址自动注入 `crypto.randomUUID` polyfill，保证前端 RPC 可用。
- 状态可视：宿主日志与设置卡片显示实际监听地址（绑定回环/内网时列出可达的局域网 IP:端口）；
  通过 `accessUrls` 声明的入口地址（可含 HTTPS 域名）会展示在卡片与登录页，多域名场景一眼可知该用哪个 URL。
- **无 TLS，禁绑通配/公网**：监听地址仅允许回环与内网（默认 `127.0.0.1`）；`0.0.0.0`、`::` 与公网 IP
  在保存与启动时都会被拒绝。外部访问请在前面挂 TLS 反向代理，回指本监听地址。

## 安装与激活

```sh
dsh plugin --profile web add link:<abs 路径>/dsh-auth-proxy
```

激活声明见 `cordis.patch.yml`（web profile roster 插入 `auth-proxy` 行）。本插件是宿主 +
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

**配置分层（改动前先读 `AGENTS.md`）**：解析 = base 层（dsh-settings scope，无 settings 服务时
退化为组合入口）+ 用户文件 `~/.dsh/dsh-auth-proxy.json`（**文件层权威**）。设置卡片只写该文件；
文件层是唯一持久存储，重启生效。GET `/api/dsh-auth-proxy/config` 只回 `tokenSet` 布尔，永不回传令牌值。

## 安全说明

- 代理即网络边缘：**不信任 `X-Forwarded-For`**（客户端可伪造，信任即白名单/锁定绕过），
  转发前剥离 `x-forwarded-for` / `x-real-ip`。
- **监听地址策略**：无 TLS 意味着绑到通配（`0.0.0.0`/`::`）或公网 IP 会把明文令牌暴露到网络，
  因此默认 `127.0.0.1`，且仅接受回环与内网地址（`127/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、
  `::1`）；保存（PUT）与启动（`sync()`）双重拒绝，日志与卡片会给出原因。外部访问请用 TLS 反向代理
  （nginx/Caddy 等）终止加密后回指 `127.0.0.1:8443`，`accessUrls` 里填对外域名。
- 无 TLS：即使仅内网监听，令牌仍经明文 HTTP 传输，同网段可嗅探。这是为局域网 HTTP 可用性做的取舍；
  需要加密传输时请在前方套 TLS 终结。
- 会话存内存、**永久有效**（重启 dsh 即清，所有人需重新登录）；失败计数由定时清理兜底（每 30 分钟扫描，闲置超 1 小时的记录清除）。锁定为按 IP，IPv6 字面量（如 `::1`）不匹配 IPv4 白名单。

## 开发

- 构建：`npm run build`（`tsc` 出宿主侧 `lib/types/` + `tsdown` 出浏览器侧 `lib/client.js`）。
- 类型检查：`npm run typecheck`。
- 冒烟测试：`npm run smoke`（驱动构建产物，覆盖登录流程、XFF 伪造、热更新、重建、禁用）。
- 仓库规则与安全不变式见 `AGENTS.md`；许可见 `LICENSE`（MIT）。

## 已知限制

- 会话永久有效：条目随登录数线性增长（重启清零，属预期）；失败计数表由定时清理兜底。
- `ws` 依赖当前未被引用（清理项）。
- 当前目录已是 git 仓库（初始提交已建）。