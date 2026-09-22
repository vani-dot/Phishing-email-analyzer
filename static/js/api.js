/* api.js — the HTTP layer for the front end.
 *
 * One wrapper for every call so that the CSRF header, the credentials mode
 * and the error handling are defined once. A fetch() written by hand at a
 * call site is a fetch() that will eventually forget the CSRF token.
 */
'use strict';

const API = (function () {

  function csrfToken() {
    // The CSRF cookie is deliberately readable by script — that is the point
    // of the double-submit pattern. The SESSION cookie is HttpOnly and is
    // never touched from here.
    const match = document.cookie.match(/(?:^|;\s*)pea_csrf=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  async function request(path, options) {
    options = options || {};
    const headers = Object.assign({}, options.headers || {});

    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      headers['X-CSRF-Token'] = csrfToken();
    }
    if (options.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.json);
    }

    let response;
    try {
      response = await fetch(path, {
        method: method,
        headers: headers,
        body: options.body,
        credentials: 'same-origin',
        cache: 'no-store'
      });
    } catch (err) {
      throw new APIError('Could not reach the server. Is it still running?', 0);
    }

    // An expired or revoked session anywhere in the app returns to the login
    // page rather than leaving a half-dead interface on screen.
    if (response.status === 401 && !path.endsWith('/api/login')) {
      window.location.href = '/login';
      throw new APIError('Session expired', 401);
    }

    if (response.status === 204) return null;

    let data = null;
    const type = response.headers.get('content-type') || '';
    if (type.includes('application/json')) {
      try { data = await response.json(); } catch (e) { data = null; }
    }

    if (!response.ok) {
      const detail = (data && data.detail) || `Request failed (${response.status})`;
      throw new APIError(typeof detail === 'string' ? detail : 'Request failed', response.status);
    }
    return data;
  }

  class APIError extends Error {
    constructor(message, status) {
      super(message);
      this.name = 'APIError';
      this.status = status;
    }
  }

  return {
    APIError,
    csrfToken,
    get:   (path)          => request(path),
    post:  (path, payload) => request(path, { method: 'POST', json: payload }),
    patch: (path, payload) => request(path, { method: 'PATCH', json: payload }),
    del:   (path)          => request(path, { method: 'DELETE' }),
    upload: (path, formData) => request(path, { method: 'POST', body: formData })
  };
})();
