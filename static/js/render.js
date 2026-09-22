/* render.js — DOM construction helpers.
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE: text supplied by an analysed email
 * never becomes markup.
 *
 * This application's entire job is to display attacker-written content —
 * subjects, sender names, body excerpts, URLs, filenames. Writing any of that
 * through innerHTML would mean a phishing email could carry a payload that
 * runs in the analyst's session the moment they inspect it, which turns the
 * security tool into the attack vector.
 *
 * So there is exactly one way to put text on the screen here, el(), and it
 * only ever assigns textContent. The Content-Security-Policy (script-src
 * 'self', no unsafe-inline) is the second layer: even a mistake in this file
 * yields a blocked console message rather than an executed script.
 */
'use strict';

const R = (function () {

  /* el('div.class#id', {attrs}, [children | 'text']) */
  function el(spec, attrs, children) {
    const parts = String(spec).split(/(?=[.#])/);
    const node = document.createElement(parts[0] || 'div');

    parts.slice(1).forEach(part => {
      if (part[0] === '.') node.classList.add(part.slice(1));
      else if (part[0] === '#') node.id = part.slice(1);
    });

    if (attrs) {
      Object.keys(attrs).forEach(key => {
        const value = attrs[key];
        if (value === null || value === undefined || value === false) return;
        if (key === 'text') {
          node.textContent = String(value);           // the only text path
        } else if (key === 'onClick') {
          node.addEventListener('click', value);
        } else if (key === 'dataset') {
          Object.keys(value).forEach(k => { node.dataset[k] = String(value[k]); });
        } else if (key === 'html') {
          // Reserved for inline SVG icons defined in this file only. Never
          // called with anything that came from the server.
          node.innerHTML = value;
        } else {
          node.setAttribute(key, String(value));
        }
      });
    }

    if (children !== undefined && children !== null) {
      (Array.isArray(children) ? children : [children]).forEach(child => {
        if (child === null || child === undefined || child === false) return;
        node.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
      });
    }
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function mount(node, children) {
    clear(node);
    (Array.isArray(children) ? children : [children]).forEach(child => {
      if (child) node.appendChild(child);
    });
    return node;
  }

  /* ---- formatting ---- */

  function when(iso) {
    if (!iso) return '—';
    // Stored timestamps are UTC without a zone marker; tell Date so.
    const date = new Date(/[Z+]/.test(iso) ? iso : iso + 'Z');
    if (isNaN(date)) return String(iso).slice(0, 16).replace('T', ' ');
    const diff = (Date.now() - date.getTime()) / 1000;
    if (diff < 60)    return 'just now';
    if (diff < 3600)  return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function exact(iso) {
    if (!iso) return '';
    const date = new Date(/[Z+]/.test(iso) ? iso : iso + 'Z');
    return isNaN(date) ? String(iso) : date.toLocaleString();
  }

  function truncate(text, max) {
    text = String(text === null || text === undefined ? '' : text);
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  }

  const SEVERITY_COLORS = {
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)',
    LOW: 'var(--low)', INFO: 'var(--info)'
  };
  const VERDICT_COLORS = {
    PHISHING: 'var(--critical)', SUSPICIOUS: 'var(--high)',
    SPAM: 'var(--medium)', GENUINE: 'var(--safe)'
  };

  function scoreColor(score) {
    if (score >= 70) return 'var(--critical)';
    if (score >= 35) return 'var(--high)';
    if (score >= 18) return 'var(--medium)';
    return 'var(--safe)';
  }

  function badge(text, variant) {
    return el('span.badge', { text: text, class: 'badge badge-' + variant });
  }

  function verdictBadge(verdict) {
    return el('span.badge', { text: verdict, class: 'badge verdict-' + verdict });
  }

  function scorePill(score) {
    const pill = el('span.score-pill', { text: String(score) });
    pill.style.color = scoreColor(score);
    pill.style.background = 'color-mix(in srgb, ' + scoreColor(score) + ' 14%, transparent)';
    return pill;
  }

  function empty(title, sub) {
    return el('div.empty', {}, [
      el('div.empty-title', { text: title }),
      sub ? el('div.empty-sub', { text: sub }) : null
    ]);
  }

  const chevron = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
                  'stroke-linecap="round" stroke-linejoin="round" width="15" height="15">' +
                  '<path d="M9 18l6-6-6-6"></path></svg>';

  return { el, clear, mount, when, exact, truncate, badge, verdictBadge,
           scorePill, scoreColor, empty, chevron, SEVERITY_COLORS, VERDICT_COLORS };
})();
