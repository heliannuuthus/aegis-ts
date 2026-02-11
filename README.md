# @aegis/sdk

Aegis Auth SDK - 支持 Web 和小程序的认证 SDK。

## 特性

- **OAuth 2.1 + PKCE**: 完整支持 OAuth 2.1 规范和 PKCE 流程
- **多平台支持**: 支持 Web 浏览器和 Taro 小程序（微信/抖音/支付宝）
- **自动 Token 管理**: 自动刷新过期 Token
- **TypeScript**: 完整的类型定义
- **轻量级**: 零运行时依赖

## 安装

```bash
npm install @aegis/sdk
# 或
pnpm add @aegis/sdk
```

## 快速开始

### Web 浏览器

```typescript
import { createWebAuthClient } from '@aegis/sdk/web';

const auth = createWebAuthClient({
  issuer: 'https://auth.example.com',
  clientId: 'your-client-id',
  audience: 'your-service-id',
  redirectUri: 'https://app.example.com/auth/callback',
  scopes: ['openid', 'profile'],
});

// 跳转到登录页
await auth.loginWithRedirect();

// 在回调页面处理登录结果
const result = await auth.handleRedirectCallback();
if (result.success) {
  window.location.href = result.redirectTo;
}

// 获取 Access Token
const token = await auth.getAccessToken();

// 获取用户信息
const user = await auth.getUserInfo();

// 登出
await auth.logout();
```

### Taro 小程序

```typescript
import { createTaroAuthClient } from '@aegis/sdk/taro';

const auth = createTaroAuthClient({
  issuer: 'https://api.example.com',
  debug: true,
});

// 一键登录（自动获取登录码）
await auth.login();

// 或使用自定义登录码
await auth.loginWithCode({
  code: loginCode,
  nickname: '用户昵称',
  avatar: 'https://example.com/avatar.png',
});

// 获取 Access Token
const token = await auth.getAccessToken();

// 获取用户信息
const user = await auth.getUserInfo();

// 绑定手机号
await auth.bindPhone(phoneCode);

// 登出
await auth.logout();
```

## API 参考

### Web Auth Client

#### `createWebAuthClient(config)`

创建 Web Auth Client 实例。

```typescript
interface WebAuthConfig {
  issuer: string;          // 认证服务器地址
  clientId: string;        // 应用 Client ID
  audience: string;        // 目标服务 ID
  redirectUri?: string;    // 重定向 URI
  scopes?: string[];       // 请求的 scope 列表
  debug?: boolean;         // 启用调试日志
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `loginWithRedirect()` | 跳转到登录页面 |
| `handleRedirectCallback()` | 处理登录回调 |
| `getAccessToken()` | 获取 Access Token（自动刷新） |
| `getUserInfo()` | 获取用户信息 |
| `logout()` | 登出 |
| `isAuthenticated()` | 检查是否已登录 |
| `requireAuth()` | 路由守卫 |

### Taro Auth Client

#### `createTaroAuthClient(config)`

创建 Taro Auth Client 实例。

```typescript
interface TaroAuthConfig {
  issuer: string;          // 认证服务器地址
  idp?: IDPType;           // 自定义 IDP（默认自动检测）
  debug?: boolean;         // 启用调试日志
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `login()` | 一键登录 |
| `loginWithCode(params)` | 使用自定义登录码登录 |
| `getAccessToken()` | 获取 Access Token |
| `getUserInfo()` | 获取用户信息 |
| `updateUserInfo(data)` | 更新用户信息 |
| `bindPhone(phoneCode)` | 绑定手机号 |
| `logout()` | 登出 |
| `isAuthenticated()` | 检查是否已登录 |

## 事件监听

```typescript
// 监听登录事件
auth.on('login', (event) => {
  console.log('用户已登录', event.data);
});

// 监听登出事件
auth.on('logout', () => {
  console.log('用户已登出');
});

// 监听 Token 刷新事件
auth.on('token_refreshed', (event) => {
  console.log('Token 已刷新', event.data);
});

// 监听 Token 过期事件
auth.on('token_expired', () => {
  console.log('Token 已过期');
});
```

## 自定义存储

```typescript
import { AuthClient } from '@aegis/sdk';

const customStorage = {
  getItem: (key) => AsyncStorage.getItem(key),
  setItem: (key, value) => AsyncStorage.setItem(key, value),
  removeItem: (key) => AsyncStorage.removeItem(key),
};

const auth = new AuthClient({
  issuer: 'https://auth.example.com',
  clientId: 'your-client-id',
  audience: 'your-service-id',
  redirectUri: 'https://app.example.com/callback',
  storage: customStorage,
});
```

## 工具函数

```typescript
import { 
  generatePKCE, 
  parseJWT, 
  isJWTExpired 
} from '@aegis/sdk';

// 生成 PKCE 参数
const pkce = await generatePKCE();
console.log(pkce.codeVerifier, pkce.codeChallenge);

// 解析 JWT
const claims = parseJWT(token);
console.log(claims.sub, claims.exp);

// 检查 JWT 是否过期
const expired = isJWTExpired(token);
```

## 相关项目

- **Aegis UI**: `aegis-ui` - 认证界面
- **Helios**: 后端服务

## License

MIT
