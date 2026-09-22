/* login.js */
'use strict';

document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('login-form');
  const error = document.getElementById('error');
  const notice = document.getElementById('notice');
  const submit = document.getElementById('submit');

  if (new URLSearchParams(window.location.search).get('expired') === '1') {
    notice.textContent = 'Your session expired. Please sign in again.';
    notice.hidden = false;
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    error.hidden = true;
    submit.disabled = true;
    submit.textContent = 'Signing in…';

    try {
      const result = await API.post('/api/login', {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      });
      window.location.href = result.must_change_password ? '/' : '/';
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      document.getElementById('password').value = '';
      submit.disabled = false;
      submit.textContent = 'Sign in';
    }
  });
});
