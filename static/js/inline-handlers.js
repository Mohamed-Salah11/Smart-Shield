/*
 * inline-handlers.js — global delegator for migrated inline event handlers.
 *
 * Strict CSP (script-src without 'unsafe-inline') blocks `<button onclick="...">`
 * attributes. scripts/migrate_handlers.py rewrites every inline handler into a
 * `data-action="<id>"` attribute and stores the original body as
 *
 *     SSActions['<id>'] = function (event, el) { ...original body... };
 *
 * This file installs a single delegator at the document level that dispatches
 * the matching SSActions entry on the corresponding event. New handlers can be
 * registered at any time via `SSActions.<id> = function (event, el) { ... }`.
 *
 * Handler context:
 *   - `event` — the DOM Event
 *   - `el`    — the element that carried the data-action attribute
 *   - `this`  — same as `el` (handlers may use either)
 *
 * Looking up the value of `event.target`, `event.currentTarget`, etc. works as
 * usual; the delegator only forwards the lookup, it does not change semantics.
 *
 * Helpers (`SSActions.__helpers`):
 *   - removeNode(id)             — convenience for the dynamic-passlist UX
 *   - closeOnBackdrop(event, el) — for click-on-backdrop dismissers (the
 *                                  delegator passes `event` and `el`, so the
 *                                  handler can re-implement the original
 *                                  `event.target === this` guard)
 */
(function () {
    "use strict";

    if (window.SSActions) return; // idempotent — base.html may load this twice

    var registry = Object.create(null);
    window.SSActions = new Proxy(registry, {
        set: function (obj, key, val) { obj[key] = val; return true; },
        get: function (obj, key) { return obj[key]; }
    });

    // ── Built-in helpers ────────────────────────────────────────────────────
    registry.__noop = function () {};

    registry.removeNode = function (event, el) {
        var id = el && el.dataset ? el.dataset.target : null;
        if (id) {
            var node = document.getElementById(id);
            if (node) node.remove();
        }
    };

    // Shared `data-action="confirm-delete" data-confirm="…"` handler. Returning
    // false makes the delegator preventDefault (cancels the surrounding form
    // submit / link navigation) — see the dispatch() return-value handling below.
    registry["confirm-delete"] = function (event, el) {
        var msg = (el && el.dataset && el.dataset.confirm) || "Are you sure?";
        if (!window.confirm(msg)) return false;
    };

    registry.closeOnBackdrop = function (event, el) {
        // Only fire when the click was on the backdrop itself, not children.
        if (event.target !== el) return;
        var actionId = el.dataset.backdropAction;
        if (actionId && typeof registry[actionId] === "function") {
            registry[actionId].call(el, event, el);
        }
    };

    // ── Delegator ───────────────────────────────────────────────────────────
    var EVENTS = [
        "click", "change", "submit", "input", "focus", "blur",
        "keydown", "keyup", "keypress", "mouseover", "mouseout",
        "dblclick", "contextmenu", "mousedown", "mouseup"
    ];

    function dispatch(eventName) {
        return function (event) {
            // Walk up from event.target to find the nearest element carrying
            // a data-action-<eventName> or data-action attribute.
            var node = event.target;
            while (node && node !== document) {
                if (node.dataset) {
                    var actionKey = "action" + eventName.charAt(0).toUpperCase() + eventName.slice(1);
                    var actionId = node.dataset[actionKey] || (eventName === "click" ? node.dataset.action : null);
                    if (actionId) {
                        var fn = registry[actionId];
                        if (typeof fn === "function") {
                            // Honor the legacy `return false` convention: an inline
                            // handler such as `onsubmit="return confirm(...)"` cancels
                            // the default action (and propagation) when it returns false.
                            var result = fn.call(node, event, node);
                            if (result === false) {
                                event.preventDefault();
                                event.stopPropagation();
                                if (typeof event.stopImmediatePropagation === "function") {
                                    event.stopImmediatePropagation();
                                }
                            }
                        }
                        return;
                    }
                }
                node = node.parentNode;
            }
        };
    }

    function install() {
        EVENTS.forEach(function (name) {
            document.addEventListener(name, dispatch(name), true);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", install);
    } else {
        install();
    }
})();
