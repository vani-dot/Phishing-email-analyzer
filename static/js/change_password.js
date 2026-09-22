/* change_password.js */
'use strict';

document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('change-form');
  const error = document.getElementById('error');
  const submit = document.getElementById('submit');

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    error.hidden = true;

    const next = document.getElementById('next').value;
    if (next !== document.getElementById('confirm').value) {
      error.textContent = 'The two new passwords do not match.';
      error.hidden = false;
      return;
    }

    submit.disabled = true;
    submit.textContent = 'Saving…';
    try {
      await API.post('/api/change-password', {
        current_password: document.getElementById('current').value,
        new_password: next
      });
      window.location.href = '/';
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      submit.disabled = false;
      submit.textContent = 'Set password';
    }
  });
});
