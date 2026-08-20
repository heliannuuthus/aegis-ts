<p align="center">
  <img src="./assets/brand/hero-ice.png" width="256" alt="Aegis TypeScript logo" />
</p>

<h1 align="center">Aegis TypeScript</h1>

`@heliannuuthus/aegis-ts` 是给浏览器用的认证 SDK。它把 OAuth 2.1 + PKCE 那一整套封装好，帮你处理登录跳转、回调校验、令牌的生命周期和用户信息读取，跟框架无关——React、Vue 都能用，也不逼你绑定任何框架。它分两层：`Auth` 是底层纯逻辑（不碰 DOM，适合自己定制存储和 HTTP 客户端），`WebAuth` 是浏览器封装（把跳转、回调、URL 解析接好，SPA 直接用）。运行时依赖刻意压得很轻，核心只依赖 `paseto-ts`。

`@heliannuuthus/aegis-ts` is a framework-agnostic browser SDK for OAuth 2.1 + PKCE. It handles redirects, callback validation, the token lifecycle, and user info. Two layers: `Auth` is the pure-logic core (no DOM, pluggable storage/HTTP), `WebAuth` is the browser wrapper that wires up redirects and URL parsing for SPAs.