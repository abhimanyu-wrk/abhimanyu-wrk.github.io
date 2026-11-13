/**
 * Safe DOM helpers (strictly textContent-based for dynamic values),
 * accessible clipboard copy controls, and keyboard-navigable tooltips.
 */

export function clearNode(node) {
  while (node && node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

/**
 * Create a DOM element safely without innerHTML.
 * @param {string} tag
 * @param {object} [props]
 * @param  {...(Node|string|null|undefined|false)} children
 */
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, val] of Object.entries(props)) {
      if (val === null || val === undefined || val === false) continue;
      if (key === 'className') {
        node.className = val;
      } else if (key === 'text') {
        node.textContent = String(val);
      } else if (key === 'dataset' && typeof val === 'object') {
        for (const [dKey, dVal] of Object.entries(val)) {
          if (dVal !== undefined && dVal !== null) {
            node.dataset[dKey] = String(dVal);
          }
        }
      } else if (key.startsWith('on') && typeof val === 'function') {
        node.addEventListener(key.slice(2).toLowerCase(), val);
      } else if (key === 'disabled' || key === 'open' || key === 'hidden') {
        node[key] = Boolean(val);
      } else {
        node.setAttribute(key, String(val));
      }
    }
  }

  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    if (child instanceof Node) {
      node.appendChild(child);
    } else {
      node.appendChild(document.createTextNode(String(child)));
    }
  }
  return node;
}

/**
 * Copy text cleanly to the clipboard without persisting data.
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  const value = String(text ?? '');
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      // Fallback below for restricted contexts
    }
  }

  try {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    document.body.appendChild(textarea);
    textarea.focus({ preventScroll: true });
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

/**
 * Create a clean Copy button with temporary state confirmation.
 * @param {() => string} getText
 * @param {string} ariaLabel
 * @param {string} [buttonLabel]
 */
export function createCopyButton(getText, ariaLabel, buttonLabel = 'Copy') {
  let resetTimer = null;
  const btn = el(
    'button',
    {
      type: 'button',
      className: 'btn-copy',
      'aria-label': ariaLabel,
      title: ariaLabel,
    },
    el('span', { className: 'btn-copy-label', text: buttonLabel })
  );

  btn.addEventListener('click', async () => {
    const labelNode = btn.querySelector('.btn-copy-label');
    const ok = await copyToClipboard(getText());
    if (resetTimer) clearTimeout(resetTimer);
    btn.classList.toggle('is-copied', ok);
    btn.classList.toggle('is-error', !ok);
    if (labelNode) labelNode.textContent = ok ? 'Copied' : 'Failed';
    resetTimer = setTimeout(() => {
      btn.classList.remove('is-copied', 'is-error');
      if (labelNode) labelNode.textContent = buttonLabel;
    }, 1600);
  });

  return btn;
}

let tooltipDelegationAttached = false;

function ensureTooltipDelegation() {
  if (tooltipDelegationAttached || typeof document === 'undefined') return;
  tooltipDelegationAttached = true;

  document.addEventListener('click', (e) => {
    const openWraps = document.querySelectorAll('.tooltip-wrap.is-open');
    for (const wrap of openWraps) {
      if (!wrap.contains(e.target)) {
        wrap.classList.remove('is-open');
        const btn = wrap.querySelector('.tooltip-trigger');
        if (btn) btn.setAttribute('aria-expanded', 'false');
      }
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const openWraps = document.querySelectorAll('.tooltip-wrap.is-open');
    for (const wrap of openWraps) {
      wrap.classList.remove('is-open');
      const btn = wrap.querySelector('.tooltip-trigger');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }
  });
}

/**
 * Accessible tooltip trigger button with hover/focus/click popover.
 * @param {string} term
 * @param {string} explanation
 */
export function createTooltip(term, explanation) {
  ensureTooltipDelegation();
  const wrapper = el('span', { className: 'tooltip-wrap' });
  const tipId = `tip-${Math.random().toString(36).slice(2, 9)}`;

  const trigger = el(
    'button',
    {
      type: 'button',
      className: 'tooltip-trigger',
      'aria-label': `Explain ${term}`,
      'aria-describedby': tipId,
      'aria-expanded': 'false',
    },
    '?'
  );

  const popup = el(
    'span',
    {
      id: tipId,
      role: 'tooltip',
      className: 'tooltip-bubble',
    },
    el('strong', { className: 'tooltip-term', text: term }),
    el('span', { className: 'tooltip-text', text: explanation })
  );

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = wrapper.classList.contains('is-open');
    for (const openWrap of document.querySelectorAll('.tooltip-wrap.is-open')) {
      openWrap.classList.remove('is-open');
      const btn = openWrap.querySelector('.tooltip-trigger');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }
    if (!wasOpen) {
      wrapper.classList.add('is-open');
      trigger.setAttribute('aria-expanded', 'true');
    }
  });

  wrapper.appendChild(trigger);
  wrapper.appendChild(popup);
  return wrapper;
}

/**
 * Format timestamp nicely for analysis audit metadata.
 * @param {Date} [date]
 */
export function formatTimestamp(date = new Date()) {
  const local = date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  return {
    local,
    iso: date.toISOString(),
    display: `${local} (${date.toISOString()})`,
  };
}
