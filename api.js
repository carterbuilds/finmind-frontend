/**
 * FinMind API Client
 * ==================
 * Standalone JS module — works in browser (vanilla/HTML) AND Next.js.
 *
 * Usage (browser):
 *   <script src="api.js"></script>
 *   const user = await FinMindAPI.auth.login('email', 'pass')
 *
 * Usage (Next.js / ESM):
 *   import FinMindAPI from './api'
 *   const txns = await FinMindAPI.transactions.list()
 */

// ─── CONFIG ──────────────────────────────────────────────────────
const API_BASE = typeof window !== 'undefined'
  ? (window.FINMIND_API_URL || 'http://localhost:3001/api')
  : (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api');

// ─── TOKEN STORAGE ────────────────────────────────────────────────
const Storage = {
  get  : (key)       => { try { return localStorage.getItem(key) }  catch { return null } },
  set  : (key, val)  => { try { localStorage.setItem(key, val) }    catch {} },
  del  : (key)       => { try { localStorage.removeItem(key) }      catch {} },
  clear: ()          => { try { localStorage.clear() }              catch {} },
};

const Token = {
  getAccess  : ()    => Storage.get('fm_access_token'),
  getRefresh : ()    => Storage.get('fm_refresh_token'),
  setAccess  : (t)   => Storage.set('fm_access_token', t),
  setRefresh : (t)   => Storage.set('fm_refresh_token', t),
  setAll     : (a,r) => { Token.setAccess(a); Token.setRefresh(r) },
  clearAll   : ()    => { Storage.del('fm_access_token'); Storage.del('fm_refresh_token'); Storage.del('fm_user') },
};

// ─── EVENT BUS (for auth state changes) ──────────────────────────
const Events = {
  _listeners: {},
  on(event, cb)  { (this._listeners[event] = this._listeners[event] || []).push(cb) },
  off(event, cb) { this._listeners[event] = (this._listeners[event]||[]).filter(f=>f!==cb) },
  emit(event, data) { (this._listeners[event]||[]).forEach(cb => cb(data)) },
};

// ─── CORE FETCH ───────────────────────────────────────────────────
let _isRefreshing   = false;
let _refreshQueue   = [];

async function request(method, path, body, opts = {}) {
  const url     = `${API_BASE}${path}`;
  const headers = { 'Content-Type': 'application/json', ...opts.headers };

  const accessToken = Token.getAccess();
  if (accessToken && !opts.skipAuth) headers['Authorization'] = `Bearer ${accessToken}`;

  const config = {
    method,
    headers,
    ...(body && !(body instanceof FormData) ? { body: JSON.stringify(body) } : {}),
    ...(body instanceof FormData            ? { body, headers: { Authorization: headers.Authorization } } : {}),
  };

  let res = await fetch(url, config);

  // ── Auto refresh on 401 ──
  if (res.status === 401 && !opts.skipAuth && !opts._retry) {
    const refreshToken = Token.getRefresh();
    if (!refreshToken) {
      _handleAuthFailure();
      throw new APIError('Session expired. Please log in again.', 401);
    }

    if (_isRefreshing) {
      // Queue the request until refresh completes
      return new Promise((resolve, reject) => {
        _refreshQueue.push({ resolve, reject });
      }).then(() => request(method, path, body, { ...opts, _retry: true }));
    }

    _isRefreshing = true;
    try {
      const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
        method : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body   : JSON.stringify({ refreshToken }),
      });

      if (!refreshRes.ok) throw new Error('Refresh failed');

      const { accessToken: newAccess, refreshToken: newRefresh } = await refreshRes.json();
      Token.setAll(newAccess, newRefresh);

      _refreshQueue.forEach(q => q.resolve());
      _refreshQueue = [];

      // Retry original request with new token
      headers['Authorization'] = `Bearer ${newAccess}`;
      res = await fetch(url, { ...config, headers });
    } catch {
      _refreshQueue.forEach(q => q.reject());
      _refreshQueue = [];
      _handleAuthFailure();
      throw new APIError('Session expired. Please log in again.', 401);
    } finally {
      _isRefreshing = false;
    }
  }

  // Parse response
  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();

  if (!res.ok) {
    throw new APIError(data?.error || data || 'Request failed', res.status, data);
  }

  return data;
}

function _handleAuthFailure() {
  Token.clearAll();
  Events.emit('auth:logout', null);
}

// Shorthand helpers
const get    = (path, opts)        => request('GET',    path, null, opts);
const post   = (path, body, opts)  => request('POST',   path, body, opts);
const patch  = (path, body, opts)  => request('PATCH',  path, body, opts);
const put    = (path, body, opts)  => request('PUT',    path, body, opts);
const del    = (path, opts)        => request('DELETE', path, null, opts);

// ─── API ERROR CLASS ──────────────────────────────────────────────
class APIError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name   = 'APIError';
    this.status = status;
    this.data   = data;
  }
}

// ─── AUTH ─────────────────────────────────────────────────────────
const auth = {
  async register(email, password, fullName, currency = 'USD', language = 'EN') {
    const data = await post('/auth/register', { email, password, fullName, currency, language }, { skipAuth: true });
    Token.setAll(data.accessToken, data.refreshToken);
    Storage.set('fm_user', JSON.stringify(data.user));
    Events.emit('auth:login', data.user);
    return data;
  },

  async login(email, password) {
    const data = await post('/auth/login', { email, password }, { skipAuth: true });
    Token.setAll(data.accessToken, data.refreshToken);
    Storage.set('fm_user', JSON.stringify(data.user));
    Events.emit('auth:login', data.user);
    return data;
  },

  async logout() {
    try {
      await post('/auth/logout', { refreshToken: Token.getRefresh() }, { skipAuth: true });
    } catch (_) {}
    Token.clearAll();
    Events.emit('auth:logout', null);
  },

  async logoutAll() {
    await post('/auth/logout-all', {});
    Token.clearAll();
    Events.emit('auth:logout', null);
  },

  isLoggedIn() {
    return !!Token.getAccess();
  },

  getCurrentUser() {
    try { return JSON.parse(Storage.get('fm_user') || 'null') } catch { return null }
  },

  onLogin (cb) { Events.on('auth:login',  cb) },
  onLogout(cb) { Events.on('auth:logout', cb) },
};

// ─── USERS ────────────────────────────────────────────────────────
const users = {
  me: () => get('/users/me'),

  update: (data) => patch('/users/me', data),

  changePassword: (currentPassword, newPassword) =>
    patch('/users/me/password', { currentPassword, newPassword }),

  deleteAccount: (password) =>
    del('/users/me', { headers: {} }),  // Note: pass password in body manually if needed
};

// ─── TRANSACTIONS ─────────────────────────────────────────────────
const transactions = {
  /**
   * List transactions with optional filters
   * @param {Object} params - { page, limit, type, categoryId, startDate, endDate, search, sortBy, sortDir }
   */
  list(params = {}) {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== '')
    ).toString();
    return get(`/transactions${qs ? '?' + qs : ''}`);
  },

  get: (id) => get(`/transactions/${id}`),

  /**
   * Get monthly summary (totals, by category, savings rate)
   * @param {number} month - 1-12
   * @param {number} year
   */
  summary: (month, year) => {
    const now = new Date();
    const m = month || now.getMonth() + 1;
    const y = year  || now.getFullYear();
    return get(`/transactions/summary?month=${m}&year=${y}`);
  },

  /**
   * Create a transaction (auto AI-classifies by default)
   * @param {Object} data - { merchant, amount, type, date, notes?, categoryId?, autoClassify? }
   */
  create: (data) => post('/transactions', data),

  update: (id, data) => put(`/transactions/${id}`, data),

  delete: (id) => del(`/transactions/${id}`),

  /**
   * Import transactions from a CSV File object
   * @param {File} file
   */
  async importCSV(file) {
    const form = new FormData();
    form.append('file', file);
    return request('POST', '/transactions/import/csv', form);
  },
};

// ─── CATEGORIES ───────────────────────────────────────────────────
const categories = {
  list: () => get('/categories'),
  get : (id) => get(`/categories/${id}`),
};

// ─── BUDGETS ──────────────────────────────────────────────────────
const budgets = {
  /**
   * List budgets with real-time spent amounts
   * @param {number} month
   * @param {number} year
   */
  list(month, year) {
    const now = new Date();
    const m = month || now.getMonth() + 1;
    const y = year  || now.getFullYear();
    return get(`/budgets?month=${m}&year=${y}`);
  },

  create: (data) => post('/budgets', data),
  update: (id, data) => put(`/budgets/${id}`, data),
  delete: (id) => del(`/budgets/${id}`),

  /** AI-generated budget suggestions based on income (Pro/Premium only) */
  suggest: () => post('/budgets/suggest', {}),
};

// ─── INSIGHTS ─────────────────────────────────────────────────────
const insights = {
  list   : (params = {}) => get(`/insights?${new URLSearchParams(params)}`),
  generate: ()           => post('/insights/generate', {}),
  markRead: (id)         => patch(`/insights/${id}/read`, {}),
  markAllRead: ()        => patch('/insights/read-all', {}),
  delete : (id)          => del(`/insights/${id}`),
};

// ─── NOTIFICATIONS ────────────────────────────────────────────────
const notifications = {
  list    : (params = {}) => get(`/notifications?${new URLSearchParams(params)}`),
  markRead: (id)          => patch(`/notifications/${id}/read`, {}),
  markAllRead: ()         => patch('/notifications/read-all', {}),
  delete  : (id)          => del(`/notifications/${id}`),
};

// ─── HEALTH SCORE ─────────────────────────────────────────────────
const healthScore = {
  get    : () => get('/health-score'),
  history: () => get('/health-score/history'),
};

// ─── UTILITY HELPERS ─────────────────────────────────────────────
const utils = {
  /**
   * Paginate through all results automatically
   * @param {Function} listFn - e.g. transactions.list
   * @param {Object}   params
   */
  async fetchAll(listFn, params = {}) {
    const firstPage = await listFn({ ...params, page: 1, limit: 50 });
    const all       = [...(firstPage.data || [])];
    const pages     = firstPage.pagination?.pages || 1;

    for (let p = 2; p <= pages; p++) {
      const page = await listFn({ ...params, page: p, limit: 50 });
      all.push(...(page.data || []));
    }
    return all;
  },

  /** Format amount: $1,234.56 or Rp1.234.567 */
  formatAmount(usdAmount, currency = 'USD', rate = 16200) {
    if (currency === 'IDR') {
      const idr = Math.round(usdAmount * rate);
      if (idr >= 1_000_000_000) return `Rp${(idr / 1_000_000_000).toFixed(1)}M`;
      if (idr >= 1_000_000)     return `Rp${(idr / 1_000_000).toFixed(1)}jt`;
      return `Rp${idr.toLocaleString('id-ID')}`;
    }
    return `$${usdAmount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  },

  /** Convert USD → IDR */
  toIDR(usdAmount, rate = 16200) { return Math.round(usdAmount * rate) },

  /** Convert IDR → USD */
  toUSD(idrAmount, rate = 16200) { return idrAmount / rate },
};

// ─── EXPORT ───────────────────────────────────────────────────────
const FinMindAPI = {
  auth,
  users,
  transactions,
  categories,
  budgets,
  insights,
  notifications,
  healthScore,
  utils,
  APIError,
  Events,
};

// Browser global
if (typeof window !== 'undefined') window.FinMindAPI = FinMindAPI;

// ESM / CommonJS export
if (typeof module !== 'undefined') module.exports = FinMindAPI;
if (typeof exports !== 'undefined') exports.default = FinMindAPI;
