<p align="center">
  <img src="./assets/brand/hero-ice.png" width="256" alt="Aegis TypeScript logo" />
</p>

<h1 align="center">Aegis TypeScript</h1>

`@heliantheons/aegis-ts` 是给浏览器用的认证 SDK。它把 OAuth 2.1 + PKCE 那一整套封装好，帮你处理登录跳转、回调校验、令牌的生命周期和用户信息读取，跟框架无关——React、Vue 都能用，也不逼你绑定任何框架。它分两层：`Auth` 是底层纯逻辑（不碰 DOM，适合自己定制存储和 HTTP 客户端），`WebAuth` 是浏览器封装（把跳转、回调、URL 解析接好，SPA 直接用）。运行时依赖刻意压得很轻，核心只依赖 `paseto-ts`。

`@heliantheons/aegis-ts` is a framework-agnostic browser SDK for OAuth 2.1 + PKCE. It handles redirects, callback validation, the token lifecycle, and user info. Two layers: `Auth` is the pure-logic core (no DOM, pluggable storage/HTTP), `WebAuth` is the browser wrapper that wires up redirects and URL parsing for SPAs.

## 安装 / Install

```bash
pnpm add @heliantheons/aegis-ts
```

所有公共 API 都可以从包根入口导入。`/web` 子路径继续保留，用于兼容旧版本调用方。

All public APIs are available from the package root. The `/web` subpath remains available for backward compatibility.

```ts
import {
  Auth,
  WebAuth,
  AuthError,
  type AuthConfig,
  type WebAuthConfig,
} from "@heliantheons/aegis-ts";
```

## 浏览器应用 / Browser applications

```ts
import { WebAuth } from "@heliantheons/aegis-ts";

const auth = new WebAuth({
  endpoint: "https://aegis.example.com",
  clientId: "portal",
  redirectUri: `${window.location.origin}/auth/callback`,
});

await auth.authorize({
  audience: "hermes",
  scopes: ["openid", "profile", "offline_access"],
  returnTo: window.location.pathname + window.location.search,
});
```

在回调路由中完成 code exchange：

```ts
const result = await auth.handleRedirectCallback();
if (!result.success) throw new Error(result.error);
window.location.replace(result.redirectTo ?? "/");
```

获取指定 audience 的 access token。SDK 会在需要时使用 refresh token 更新令牌：

```ts
const token = await auth.getAccessToken("hermes");
const response = await fetch("/api/resource", {
  headers: { Authorization: `Bearer ${token}` },
});
```

## 自定义集成 / Custom integration

需要替换存储或 HTTP 实现时，可以给 `WebAuth` 传入适配器，也可以直接使用底层 `Auth`：

```ts
const auth = new WebAuth({
  endpoint: "https://aegis.example.com",
  clientId: "portal",
  redirectUri: `${window.location.origin}/auth/callback`,
  storage: customStorage,
  httpClient: customHTTPClient,
});
```

浏览器应用属于 OAuth public client，不要把 `client_secret` 放进前端代码。
