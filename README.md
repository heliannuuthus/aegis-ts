# @heliannuuthus/aegis-sdk

Aegis Auth SDK - Web 认证 SDK，支持 OAuth 2.1 + PKCE。

## 特性

- **OAuth 2.1 + PKCE**: 完整支持 OAuth 2.1 规范和 PKCE 流程
- **Auth（底层）**: 纯逻辑层，无框架依赖
- **WebAuth（浏览器）**: 针对 Web 的封装，含跳转、回调、URL 解析
- **自动 Token 管理**: 自动刷新过期 Token
- **TypeScript**: 完整的类型定义
- **轻量级**: 最小化运行时依赖

## 安装

```bash
npm install @heliannuuthus/aegis-sdk
# 或
pnpm add @heliannuuthus/aegis-sdk
```

## 快速开始

### 方式一：WebAuth（浏览器）

适用于 SPA，使用 `@heliannuuthus/aegis-sdk/web`：

```typescript
import { WebAuth } from '@heliannuuthus/aegis-sdk/web';

const auth = new WebAuth({
  endpoint: 'https://auth.example.com',
  clientId: 'your-client-id',
  redirectUri: 'https://app.example.com/auth/callback',
});

// 跳转到登录页
await auth.authorize({
  scopes: ['openid', 'profile'],
  audience: 'your-service-id',
});

// 在回调页面处理登录结果
const result = await auth.handleRedirectCallback();
if (result.success && result.redirectTo) {
  window.location.href = result.redirectTo;
}

// 获取 Access Token
const token = await auth.getAccessToken();

// 获取用户信息
const user = await auth.getUser();

// 登出
await auth.logout();
```

### 方式二：Auth（底层 API）

适用于需要自定义存储或 HTTP 客户端的场景：

```typescript
import { Auth, BrowserStorageAdapter } from '@heliannuuthus/aegis-sdk';

const auth = new Auth({
  endpoint: 'https://auth.example.com',
  clientId: 'your-client-id',
  redirectUri: 'https://app.example.com/auth/callback',
  storage: new BrowserStorageAdapter(),
});

// 获取授权 URL（不自动跳转）
const { url } = await auth.authorize({
  scopes: ['openid', 'profile'],
  audience: 'your-service-id',
});
window.location.href = url;

// 处理回调（从 URL 获取 code 和 state）
const result = await auth.handleCallback(code, state);
// result.returnTo 为登录前保存的路径
```

### React 应用集成

SDK 不提供 React 绑定。应用层可基于 Auth/WebAuth 实例，用事件订阅、SWR、zustand 等方式管理状态：

```typescript
import { Auth } from '@heliannuuthus/aegis-sdk';

const auth = new Auth({ ... });

// 方式一：事件订阅
auth.on('login', () => { /* 更新 UI */ });
auth.on('logout', () => { /* 更新 UI */ });

// 方式二：SWR 等数据获取
const { data: user } = useSWR('auth-user', () => auth.getUser(), { ... });
```

## API 参考

### WebAuth (`@heliannuuthus/aegis-sdk/web`)

```typescript
interface WebAuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri?: string;
}
```

| 方法 | 说明 |
|------|------|
| `authorize(params)` | 跳转到登录页，支持 `scopes`、`audience`、`audiences`、`returnTo` 等 |
| `handleRedirectCallback()` | 处理 OAuth 回调，返回 `{ success, error?, redirectTo? }` |
| `getAccessToken(audience?)` | 获取 Access Token（自动刷新） |
| `getUser()` | 获取 ID Token 中的用户信息 |
| `isAuthenticated(audience?)` | 检查是否已登录 |
| `logout(options?)` | 登出，可选 `returnTo` |
| `on(event, listener)` | 监听事件 |
| `off(event, listener)` | 取消监听 |

### Auth（底层）

```typescript
interface AuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri?: string;
  storage?: StorageAdapter;
  httpClient?: HttpClient;
}
```

| 方法 | 说明 |
|------|------|
| `authorize(options)` | 返回 `{ url, pkce, state }`，不自动跳转 |
| `handleCallback(code, state)` | 处理回调，返回 `CallbackResult`（含 `returnTo`） |
| `getAccessToken(audience?)` | 获取 Access Token |
| `getUser()` | 获取用户信息 |
| `isAuthenticated(audience?)` | 检查是否已登录 |
| `logout()` | 登出 |
| `saveReturnTo(path)` | 保存登录后跳转路径 |
| `getConnections()` | 获取可用登录方式 |
| `createChallenge(req)` | 创建挑战（MFA 等） |
| `verifyChallenge(id, req)` | 验证挑战 |
| `login(req)` | 直接登录（挑战流程） |
| `on(event, listener)` | 监听事件，返回取消函数 |
| `off(event, listener)` | 取消监听 |

### 事件

```typescript
auth.on('login', (event) => { /* 登录成功 */ });
auth.on('logout', () => { /* 登出 */ });
auth.on('token_refreshed', (event) => { /* Token 刷新 */ });
auth.on('token_expired', () => { /* Token 过期 */ });
```

### 自定义存储

```typescript
import { Auth } from '@heliannuuthus/aegis-sdk';

const customStorage = {
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
};

const auth = new Auth({
  endpoint: 'https://auth.example.com',
  clientId: 'your-client-id',
  redirectUri: 'https://app.example.com/callback',
  storage: customStorage,
});
```

## 导出概览

- **类**: `Auth`, `AuthError`, `BrowserStorageAdapter`, `MemoryStorageAdapter`
- **WebAuth**: `@heliannuuthus/aegis-sdk/web`
- **类型**: `AuthConfig`, `AuthorizeOptions`, `CallbackResult`, `IDTokenClaims` 等
- **常量**: `ErrorCodes`, `VERSION`

## License

MIT
