/*
 * common.js — shared UI primitives loaded by every Smart Shield page.
 *
 * Currently exposes:
 *
 *   data-confirm="message"
 *       Attach to any <form>, <button>, or <a>. On submit/click, shows the
 *       browser's native confirm() dialog with that message. If the user
 *       cancels, the action is preempted (preventDefault + return false).
 *
 *       Replaces three ad-hoc patterns currently in use across templates:
 *           if (!confirm('...')) return;
 *           R['h_XYZ'] = function(...) { return confirm(...); };
 *           confirmAction(action, label, color)        // halt_system.html
 *
 *       Use it like:
 *           <form method="post" data-confirm="Reboot the appliance?">…</form>
 *           <a href="…" data-confirm="Delete this rule?">Delete</a>
 *
 *       Templates already using the ad-hoc patterns keep working — the shared
 *       handler is additive. Migrate page-by-page on the next touch.
 */
(function() {
  function attach(root) {
    root.querySelectorAll('[data-confirm]').forEach((el) => {
      if (el.__ssConfirmWired) return;
      el.__ssConfirmWired = true;
      const message = el.getAttribute('data-confirm') || 'Are you sure?';

      const eventName = el.tagName === 'FORM' ? 'submit' : 'click';
      el.addEventListener(eventName, (event) => {
        if (!window.confirm(message)) {
          event.preventDefault();
          event.stopPropagation();
          return false;
        }
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => attach(document));
  } else {
    attach(document);
  }

  // Late-inserted elements (modal bodies, dynamic tables) can call
  // window.ssConfirmRescan(rootEl) after they render to wire newcomers.
  window.ssConfirmRescan = attach;
})();
