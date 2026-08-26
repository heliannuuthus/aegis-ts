# Aegis TS

`@heliantheons/aegis-ts` 是 Web 认证 SDK，支持 OAuth 2.1 + PKCE、浏览器跳转、回调处理、token 管理与用户信息读取。

## 技术栈

- TypeScript ESM
- tsup 构建
- Vitest 测试
- ESLint + Prettier
- 运行时依赖尽量保持轻量，目前核心依赖为 `paseto-ts`

## 常用命令

```bash
pnpm dev
pnpm build
pnpm test
pnpm test:coverage
pnpm lint
pnpm type-check
pnpm format
```

## 模块边界

- `Auth` 是底层逻辑层，不绑定 React/Vue 等框架。
- `WebAuth` 面向浏览器 SPA，负责跳转、URL 回调、returnTo 等 Web 行为。
- SDK 不提供 React 绑定；应用层自行用事件、SWR、Zustand 等管理 UI 状态。
- API endpoint、authorize/token/challenge 语义必须与 Helios Aegis 后端保持一致。

## 开发规则

- 不要在 SDK 中硬编码业务站点、租户或环境域名。
- 存储适配器需要保持可替换；浏览器能力和纯逻辑能力要分层。
- token 刷新、错误传播、回调状态校验必须有测试覆盖。
- 修改公开类型或导出入口时，同步 README。

## 验证 Checklist

1. `pnpm type-check`
2. `pnpm test`
3. `pnpm build`
4. 涉及 lint 规则或大范围改动时运行 `pnpm lint`
