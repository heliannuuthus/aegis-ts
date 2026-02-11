/**
 * JWT 工具函数
 * 注意：这里只解析 JWT，不验证签名（签名验证由服务端完成）
 */

import type { JWTClaims } from '../types';

/**
 * Base64 URL 解码
 */
function base64UrlDecode(str: string): string {
  // 补齐 padding
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  
  try {
    return decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
  } catch {
    return atob(base64);
  }
}

/**
 * 解析 JWT（不验证签名）
 */
export function parseJWT(token: string): JWTClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = base64UrlDecode(parts[1]);
    return JSON.parse(payload) as JWTClaims;
  } catch {
    return null;
  }
}

/**
 * 检查 JWT 是否过期
 */
export function isJWTExpired(token: string, bufferSeconds: number = 60): boolean {
  const claims = parseJWT(token);
  if (!claims || !claims.exp) {
    return true;
  }

  const now = Math.floor(Date.now() / 1000);
  return claims.exp - bufferSeconds <= now;
}

/**
 * 获取 JWT 过期时间戳
 */
export function getJWTExpiresAt(token: string): number | null {
  const claims = parseJWT(token);
  if (!claims || !claims.exp) {
    return null;
  }
  return claims.exp * 1000; // 转换为毫秒
}

/**
 * 获取 JWT 中的 scope
 */
export function getJWTScope(token: string): string[] {
  const claims = parseJWT(token);
  if (!claims || !claims.scope) {
    return [];
  }
  return claims.scope.split(' ');
}
