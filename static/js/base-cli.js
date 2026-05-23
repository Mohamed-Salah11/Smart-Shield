/*
 * base-cli.js — Smart Shield Live CLI Terminal (XTerm.js + WebSocket + PTY).
 *
 * Wires the floating xterm overlay to /terminal/ws after the server issues
 * a single-use signed ticket via POST /terminal/api/ws-ticket. The ticket
 * carries the recent-reauth check, so opening the console after the reauth
 * window has lapsed shows an actionable message instead of a silent failure.
 *
 * Pure JS — no Jinja values. Loaded only when the parent template renders
 * the {% if session.is_superuser %} branch.
 */
(function() {
  let _sock = null, _term = null, _fit = null, _open = false;

  window.ssCLIToggle = function() {
    _open = !_open;
    document.getElementById('ss-cli-overlay').classList.toggle('d-none', !_open);
    if (_open) _connect();
    else _disconnect();
  };

  window.ssCLIClose = function() {
    _open = false;
    document.getElementById('ss-cli-overlay').classList.add('d-none');
    _disconnect();
  };

  function _disconnect() {
    if (_sock) { try { _sock.close(); } catch(_) {} _sock = null; }
    if (_term) { try { _term.dispose(); } catch(_) {} _term = null; }
    if (_fit)  { _fit = null; }
  }

  function _connect() {
    const container = document.getElementById('ss-cli-term');
    container.innerHTML = '';

    _term = new Terminal({
      fontSize: 13,
      fontFamily: "ui-monospace,'Cascadia Code','Fira Mono',Menlo,Consolas,monospace",
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 5000,
      theme: {
        background:        '#0d1117',
        foreground:        '#e6edf3',
        cursor:            '#58a6ff',
        cursorAccent:      '#0d1117',
        selectionBackground: 'rgba(88,166,255,.25)',
        black:             '#0d1117',
        brightBlack:       '#6e7681',
        red:               '#f85149',
        brightRed:         '#ffa198',
        green:             '#3fb950',
        brightGreen:       '#56d364',
        yellow:            '#d29922',
        brightYellow:      '#e3b341',
        blue:              '#58a6ff',
        brightBlue:        '#79c0ff',
        magenta:           '#bc8cff',
        brightMagenta:     '#d2a8ff',
        cyan:              '#39d353',
        brightCyan:        '#56d364',
        white:             '#b1bac4',
        brightWhite:       '#f0f6fc',
      },
    });

    _fit = new FitAddon.FitAddon();
    _term.loadAddon(_fit);
    _term.open(container);

    requestAnimationFrame(() => {
      _fit.fit();
      _openSocket();
    });
  }

  function _openSocket() {
    // Warning banner — operators see this every time the console opens so the
    // privilege model never becomes invisible.
    if (_term) {
      _term.write('\x1b[33m========================================================\x1b[0m\r\n');
      _term.write('\x1b[1;33m  SmartShield Appliance Console\x1b[0m\r\n');
      _term.write('\x1b[33m  Commands run with appliance-level privileges and can\r\n');
      _term.write('  change firewall rules, secrets, services, and network\r\n');
      _term.write('  access. Every command is audited.\x1b[0m\r\n');
      _term.write('\x1b[33m========================================================\x1b[0m\r\n');
    }

    // Step 1: request a single-use signed ticket — this verifies recent
    // reauth on the server side. If reauth has lapsed, surface a clear
    // message and stop. The user must trigger reauth elsewhere first.
    fetch('/terminal/api/ws-ticket', {
      method: 'POST',
      headers: { 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || '' },
      credentials: 'same-origin'
    }).then(r => r.json().then(d => ({ status: r.status, body: d })))
      .then(({status, body}) => {
        if (!body || !body.ok) {
          if (body && body.reauth_required) {
            _term.write('\r\n\x1b[31m[Re-authentication required — open any password-protected\r\n');
            _term.write(' action (e.g. Diagnostics → Halt System) to refresh your reauth,\r\n');
            _term.write(' then reopen the console.]\x1b[0m\r\n');
          } else {
            _term.write('\r\n\x1b[31m[Cannot open console: ' + (body && body.message ? body.message : ('HTTP ' + status)) + ']\x1b[0m\r\n');
          }
          return;
        }
        _openSocketWithTicket(body.ticket);
      })
      .catch(err => {
        _term.write('\r\n\x1b[31m[Cannot open console: ' + err + ']\x1b[0m\r\n');
      });
  }

  function _openSocketWithTicket(ticket) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    _sock = new WebSocket(proto + '//' + location.host + '/terminal/ws?t=' + encodeURIComponent(ticket));
    _sock.binaryType = 'arraybuffer';

    _sock.onopen = () => {
      _fit.fit();
    };

    _sock.onmessage = (e) => {
      if (!_term) return;
      const data = e.data instanceof ArrayBuffer
        ? new TextDecoder().decode(e.data) : e.data;
      _term.write(data);
    };

    _sock.onclose = () => {
      if (_term) _term.write('\r\n\x1b[31m[Session ended — close and reopen to reconnect]\x1b[0m\r\n');
    };

    _sock.onerror = () => {
      if (_term) _term.write('\r\n\x1b[31m[WebSocket connection error]\x1b[0m\r\n');
      // Probe the HTTP backend to distinguish nginx config issues from backend-down issues
      fetch('/terminal/check').then(r => r.json()).then(d => {
        if (d.ok && _term) {
          _term.write('\r\n\x1b[33m[HTTP backend reachable — nginx WebSocket config is likely missing.]\x1b[0m\r\n');
          _term.write('\x1b[33m[Add this to your nginx.conf and reload nginx:]\x1b[0m\r\n');
          _term.write('\x1b[36m  location /terminal/ws {\x1b[0m\r\n');
          _term.write('\x1b[36m      proxy_pass         http://127.0.0.1:5000;\x1b[0m\r\n');
          _term.write('\x1b[36m      proxy_http_version 1.1;\x1b[0m\r\n');
          _term.write('\x1b[36m      proxy_set_header   Upgrade    $http_upgrade;\x1b[0m\r\n');
          _term.write('\x1b[36m      proxy_set_header   Connection "upgrade";\x1b[0m\r\n');
          _term.write('\x1b[36m      proxy_read_timeout 3600s;\x1b[0m\r\n');
          _term.write('\x1b[36m  }\x1b[0m\r\n');
          _term.write('\x1b[33m[Run: nginx -t && service nginx reload]\x1b[0m\r\n');
        }
      }).catch(() => {
        if (_term) _term.write('\x1b[33m[Backend unreachable — check if SmartShield service is running.]\x1b[0m\r\n');
      });
    };

    // Keystrokes → shell
    _term.onData((data) => {
      if (_sock && _sock.readyState === WebSocket.OPEN) _sock.send(data);
    });

    // Terminal resize → pty TIOCSWINSZ
    _term.onResize(({cols, rows}) => {
      if (_sock && _sock.readyState === WebSocket.OPEN)
        _sock.send(JSON.stringify({type: 'resize', cols, rows}));
    });

    _term.focus();
  }

  window.addEventListener('resize', () => { if (_fit && _open) _fit.fit(); });
})();
