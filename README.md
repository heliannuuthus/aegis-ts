<p align="center">
  <img src="./assets/brand/hero-ice.png" width="256" alt="Aegis TypeScript logo" />
</p>

<h1 align="center">Aegis TypeScript</h1>

`@heliannuuthus/aegis-ts` 是给浏览器用的认证 SDK。它把 OAuth 2.1 + PKCE 那一套流程封好，帮你处理登录跳转、回调校验、令牌的生命周期和用户信息读取，跟框架无关——React、Vue 都能用，但也不逼你绑定任何框架。

`@heliannuuthus/aegis-ts` is a framework-agnostic browser SDK for OAuth 2.1 + PKCE: redirects, callback validation, token lifecycle, and user info, with pluggable storage and HTTP adapters.

它分两层：

- **`Auth`** 是底层纯逻辑，不碰 DOM、不碰框架，适合自己定制存储或 HTTP 客户端的场景。
- **`WebAuth`** 是浏览器封装，把跳转、回调、URL 解析这些 Web 行为接好了，SPA 直接用。

运行时依赖刻意压得很轻，目前核心只依赖 `paseto-ts`。

## 安装

```bash
npm install @heliannuuthus/aegis-ts
# 或
pnpm add @heliannuuthus/aegis-ts
```

## 快速开始

### WebAuth（浏览器）

适合 SPA，从 `@heliannuuthus/aegis-ts/web` 引入：

```typescript
import { WebAuth } from "@heliannuuthus/aegis-ts/web";

const auth = new WebAuth({
  endpoint: "https://auth.example.com",
  clientId: "your-client-id",
  redirectUri: "https://app.example.com/auth/callback",
});

// 跳转到登录页
await auth.authorize({
  scopes: ["openid", "profile"],
  audience: "your-service-id",
});

// 在回调页面处理登录结果
const result = await auth.handleRedirectCallback();
if (result.success && result.redirectTo) {
  window.location.href = result.redirectTo;
}

// 获取 Access Token / 用户信息 / 登出
const token = await auth.getAccessToken();
const user = await auth.getUser();
await auth.logout();
```

### Auth（底层）

需要自定义存储或 HTTP 客户端时用这一层：

```typescript
import { Auth, BrowserStorageAdapter } from "@heliannuuthus/aegis-ts";

const auth = new Auth({
  endpoint: "https://auth.example.com",
  clientId: "your-client-id",
  redirectUri: "https://app.example.com/auth/callback",
  storage: new BrowserStorageAdapter(),
});

// 拿到授权 URL，自己决定怎么跳
const { url } = await auth.authorize({
  scopes: ["openid", "profile"],
  audience: "your-service-id",
});
window.location.href = url;

// 从回调 URL 里取 code 和 state 后处理
const result = await auth.handleCallback(code, state);
// result.returnTo 为登录前保存的路径
```

### React 集成

SDK 本身不提供 React 绑定。应用层基于 `Auth`/`WebAuth` 实例，用事件订阅、SWR、zustand 等方式自己管状态：

```typescript
import { Auth } from '@heliannuuthus/aegis-ts';

const auth = new Auth({ ... });

// 事件订阅
auth.on('login', () => { /* 更新 UI */ });
auth.on('logout', () => { /* 更新 UI */ });

// 或配合 SWR
const { data: user } = useSWR('auth-user', () => auth.getUser(), { ... });
```

## API 参考

### WebAuth (`@heliannuuthus/aegis-ts/web`)

```typescript
interface WebAuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri: string;
}
```

| 方法 | 说明 |
| --- | --- |
| `authorize(params)` | 跳转到登录页，支持 `scopes`、`audience`、`audiences`、`returnTo` 等 |
| `handleRedirectCallback()` | 处理 OAuth 回调，返回 `{ success, error?, redirectTo? }` |
| `getAccessToken(audience?)` | 获取 Access Token（自动刷新） |
| `getUser()` | 读取 ID Token 中的用户信息 |
| `isAuthenticated(audience?)` | 检查是否已登录 |
| `logout(options?)` | 登出，可选 `returnTo` |
| `on(event, listener)` / `off(event, listener)` | 订阅 / 取消事件 |

### Auth（底层）

```typescript
interface AuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri: string;
  storage?: StorageAdapter;
  httpClient?: HttpClient;
}
```

| 方法 | 说明 |
| --- | --- |
| `authorize(options)` | 返回 `{ url, pkce, state }`，不自动跳转 |
| `handleCallback(code, state)` | 处理回调，返回 `CallbackResult`（含 `returnTo`） |
| `getAccessToken(audience?)` | 获取 Access Token |
| `getUser()` | 获取用户信息 |
| `isAuthenticated(audience?)` | 检查是否已登录 |
| `logout()` | 登出 |
| `saveReturnTo(path)` | 保存登录后跳转路径 |
| `getConnections()` | 获取可用登录方式 |
| `createChallenge(req)` / `verifyChallenge(id, req)` | 创建 / 验证挑战（MFA 等） |
| `login(req)` | 提交登录，返回由 HTTP 300 `Location` 描述的下一步 |
| `on(event, listener)` / `off(event, listener)` | 订阅 / 取消事件 |

### 事件

```typescript
auth.on("login", (event) => { /* 登录成功 */ });
auth.on("logout", () => { /* 登出 */ });
auth.on("token_refreshed", (event) => { /* Token 刷新 */ });
auth.on("token_expired", () => { /* Token 过期 */ });
```

### 自定义存储

```typescript
import { Auth } from "@heliannuuthus/aegis-ts";

const customStorage = {
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
};

const auth = new Auth({
  endpoint: "https://auth.example.com",
  clientId: "your-client-id",
  redirectUri: "https://app.example.com/callback",
  storage: customStorage,
});
```

## 导出概览

- **类**: `Auth`, `AuthError`, `BrowserStorageAdapter`, `MemoryStorageAdapter`
- **WebAuth**: `@heliannuuthus/aegis-ts/web`
- **类型**: `AuthConfig`, `AuthorizeOptions`, `CallbackResult`, `IDTokenClaims` 等
- **常量**: `ErrorCodes`, `VERSION`

## License

MIT