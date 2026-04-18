import { AsyncLocalStorage } from 'node:async_hooks';

/** Cookie HTTP por pedido (UI ou env) — evita condições de corrida entre runs paralelos. */
export const ghostctfHttpCookieAls = new AsyncLocalStorage();

export function getPipelineHttpCookie() {
  const s = ghostctfHttpCookieAls.getStore();
  if (s && s.cookie != null && String(s.cookie).trim()) return String(s.cookie).trim();
  return String(process.env.GHOSTCTF_HTTP_COOKIE || '').trim();
}
