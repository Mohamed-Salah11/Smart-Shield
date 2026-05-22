/*
 * base-chrome.js — page-chrome behavior shared by every Smart Shield page.
 *
 * Responsibilities:
 *   1. Inject the CSRF token into every non-GET HTML form on submit-time.
 *      The token is read from the <meta name="csrf-token"> tag base.html
 *      emits during rendering.
 *   2. Sidebar open/close + persist state in localStorage.
 *   3. Sidebar accordion: one open group at a time.
 *   4. Highlight the active menu item based on window.location.pathname,
 *      using best-match longest-prefix and any data-match-pattern hints.
 *   5. Apply the user's saved theme from localStorage on first paint.
 *   6. Wire data-advanced toggles for "Display Advanced" sections.
 *
 * Pure JS — no Jinja values. Safe to cache.
 */
(function() {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';

    // Inject CSRF into all non-GET forms
    document.querySelectorAll('form').forEach((form) => {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        if (method === 'GET') return;
        if (form.querySelector('input[name="csrf_token"]')) return;
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = csrfToken || '';
        form.appendChild(input);
    });

    const appShell       = document.getElementById('appShell');
    const sidebarToggle  = document.getElementById('sidebarToggle');
    const sidebarClose   = document.getElementById('sidebarClose');
    const sidebarBackdrop= document.getElementById('sidebarBackdrop');

    // Restore sidebar state
    const sidebarState = localStorage.getItem('sidebarOpen');
    if (sidebarState === 'false') {
        appShell.classList.remove('sidebar-open');
    } else {
        appShell.classList.add('sidebar-open');
    }

    function openSidebar()  { appShell.classList.add('sidebar-open');    localStorage.setItem('sidebarOpen', 'true');  }
    function closeSidebar() { appShell.classList.remove('sidebar-open'); localStorage.setItem('sidebarOpen', 'false'); }

    if (sidebarToggle)   sidebarToggle.addEventListener('click', () => appShell.classList.contains('sidebar-open') ? closeSidebar() : openSidebar());
    if (sidebarClose)    sidebarClose.addEventListener('click', closeSidebar);
    if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', closeSidebar);

    // Sidebar group accordion
    (function setupAccordion() {
        const sideGroups = document.querySelectorAll('.side-group');
        sideGroups.forEach(group => {
            const summary = group.querySelector('summary');
            const content = group.querySelector('.side-links');
            if (!summary || !content) return;

            content.style.overflow   = 'hidden';
            content.style.transition = 'max-height 0.3s ease-out, opacity 0.3s ease-out';
            content.style.maxHeight  = group.hasAttribute('open') ? content.scrollHeight + 'px' : '0';
            content.style.opacity    = group.hasAttribute('open') ? '1' : '0';

            summary.addEventListener('click', function(e) {
                e.preventDefault();
                const isOpening = !group.hasAttribute('open');
                if (isOpening) {
                    sideGroups.forEach(other => {
                        if (other !== group && other.hasAttribute('open')) {
                            const oc = other.querySelector('.side-links');
                            if (oc) { oc.style.maxHeight = '0'; oc.style.opacity = '0'; }
                            setTimeout(() => other.removeAttribute('open'), 300);
                        }
                    });
                    group.setAttribute('open', '');
                    content.style.maxHeight = content.scrollHeight + 'px';
                    content.style.opacity   = '1';
                } else {
                    content.style.maxHeight = '0';
                    content.style.opacity   = '0';
                    setTimeout(() => group.removeAttribute('open'), 300);
                }
            });
        });
    })();

    // Highlight active menu item
    (function highlightActiveMenu() {
        const currentPath  = window.location.pathname.replace(/\/$/, '');
        const sidebarLinks = document.querySelectorAll('.side-links a');
        const sideGroups   = document.querySelectorAll('.side-group');

        let bestMatch = null, bestMatchLength = 0;

        sidebarLinks.forEach(link => {
            let linkPath = new URL(link.href, window.location.origin).pathname.replace(/\/$/, '');
            const matchPatternAttr = link.getAttribute('data-match-pattern');
            const matchPatterns    = matchPatternAttr ? matchPatternAttr.split(',') : [];

            let isMatch = currentPath === linkPath ||
                (linkPath !== '' && linkPath !== '/' && currentPath.startsWith(linkPath + '/')) ||
                (linkPath !== '' && linkPath !== '/' && currentPath.startsWith(linkPath));
            let matchedLength = linkPath.length;

            if (!isMatch && matchPatterns.length > 0) {
                for (const pattern of matchPatterns) {
                    const tp = pattern.trim();
                    if (currentPath === tp || currentPath.startsWith(tp + '/') || currentPath.startsWith(tp)) {
                        isMatch = true;
                        matchedLength = Math.max(matchedLength, tp.length);
                        break;
                    }
                }
            }

            if (isMatch && matchedLength > bestMatchLength) {
                bestMatch       = link;
                bestMatchLength = matchedLength;
            }
        });

        const activeGroup = bestMatch ? bestMatch.closest('.side-group') : null;

        sideGroups.forEach(group => {
            const content = group.querySelector('.side-links');
            const isActive = group === activeGroup;
            if (isActive)  group.setAttribute('open', '');
            else           group.removeAttribute('open');
            if (content) {
                content.style.transition = 'none';
                content.style.maxHeight  = isActive ? content.scrollHeight + 'px' : '0';
                content.style.opacity    = isActive ? '1' : '0';
                requestAnimationFrame(() => { content.style.transition = 'max-height 0.3s ease-out, opacity 0.3s ease-out'; });
            }
        });

        if (bestMatch) {
            bestMatch.classList.add('active');
        } else {
            const firstGroup = document.querySelector('.side-group');
            if (firstGroup) {
                firstGroup.setAttribute('open', '');
                const fc = firstGroup.querySelector('.side-links');
                if (fc) {
                    fc.style.transition = 'none';
                    fc.style.maxHeight  = fc.scrollHeight + 'px';
                    fc.style.opacity    = '1';
                    requestAnimationFrame(() => { fc.style.transition = 'max-height 0.3s ease-out, opacity 0.3s ease-out'; });
                }
            }
        }
    })();
})();

// Theme loader — applies the user's saved theme before first paint
(function() {
    const html = document.documentElement;
    try {
        const userTheme = localStorage.getItem('userTheme');
        if (userTheme) {
            const t = JSON.parse(userTheme);
            if (t['data-theme']) html.setAttribute('data-theme', t['data-theme']);
            Object.entries(t).forEach(([v, val]) => {
                if (v !== '_name' && v !== 'data-theme') html.style.setProperty(v, val);
            });
        }
    } catch(e) {}
})();

// Display Advanced toggle (global)
(function () {
    document.addEventListener('click', function (e) {
        const btn = e.target.closest('[data-advanced]');
        if (!btn) return;
        const targetId = btn.dataset.advanced;
        const panel = document.getElementById(targetId);
        if (!panel) return;
        const nowHidden = panel.classList.toggle('d-none');
        const icon = '<i class="fa fa-gear me-1"></i>';
        btn.innerHTML = nowHidden ? icon + 'Display Advanced' : icon + 'Hide Advanced';
    });
})();
