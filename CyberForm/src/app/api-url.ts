import { environment } from '../environments/environment';

/**
 * URL absolue vers le backend Flask.
 * En dev (`apiUrl` vide), chemins relatifs `/api/...` passent par le proxy Angular.
 */
export function apiUrl(path: string): string {
  const p = path.startsWith('/') ? path : `/${path}`;
  const base = (environment.apiUrl || '').replace(/\/$/, '');
  return base ? `${base}${p}` : p;
}
