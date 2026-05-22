/*
 * base-chatbot.js — Smart Shield AI chatbot UI.
 *
 * Floating chat overlay that talks to /chatbot/api/chat. Maintains the
 * message history in OpenAI format on the client and renders the
 * "pending action" card (Approve / Cancel) when the server proposes a
 * privileged change. Loaded only when the parent template renders the
 * {% if session.user_id %} branch.
 */
(function(){
  let _open = false;
  let _minimized = false;
  let _msgs = [];   // message history in OpenAI format

  function _esc(t) {
    return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function _addMsg(text, cls) {
    const el = document.createElement('div');
    el.className = 'ss-cm ' + cls;
    el.innerHTML = _esc(text).replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/\n/g,'<br>');
    const box = document.getElementById('ss-chat-messages');
    box.appendChild(el);
    el.scrollIntoView({behavior:'smooth', block:'end'});
    return el;
  }

  function _addActionCard(action) {
    const card = document.createElement('div');
    card.className = 'ss-action-card';
    card.dataset.action = JSON.stringify(action);
    card.innerHTML =
      '<div class="ss-action-summary"><i class="fa-solid fa-shield-halved"></i> ' + _esc(action.summary) + '</div>' +
      '<div class="ss-action-detail">' + _esc(action.detail) + '</div>' +
      '<div class="ss-action-btns">' +
        '<button class="ss-action-approve" data-action="h_6c0f76dfd7"><i class="fa-solid fa-check"></i> Approve</button>' +
        '<button class="ss-action-cancel"  data-action="h_379fbd0539"><i class="fa-solid fa-xmark"></i> Cancel</button>' +
      '</div>';
    const box = document.getElementById('ss-chat-messages');
    box.appendChild(card);
    card.scrollIntoView({behavior:'smooth', block:'end'});
  }

  window.ssChatApprove = async function(btn) {
    const card   = btn.closest('.ss-action-card');
    const action = JSON.parse(card.dataset.action);
    card.querySelector('.ss-action-btns').innerHTML = '<span class="ss-action-status">Applying…</span>';
    try {
      const res = await fetch('/chatbot/api/approve_action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: action, approved: true}),
      });
      let data;
      try { data = await res.json(); }
      catch(_) { data = {ok: false, reply: 'Server returned a non-JSON response (status ' + res.status + ').'}; }
      card.remove();
      if (data.ok) {
        _msgs.push({role: 'assistant', content: data.reply});
        _addMsg(data.reply, 'b');
      } else {
        _addMsg('⚠ ' + (data.reply || data.message || 'Action failed.'), 's');
      }
    } catch(e) {
      card.querySelector('.ss-action-btns').innerHTML = '<span class="ss-action-status ext-c9e34862">Error: ' + _esc(e.message) + '</span>';
    }
  };

  window.ssChatCancel = function(btn) {
    const card = btn.closest('.ss-action-card');
    card.remove();
    _addMsg('Action cancelled.', 's');
    _msgs.push({role: 'user', content: 'I changed my mind — please cancel that action.'});
  };

  window.ssChatToggle = function() {
    if (_minimized) {
      // Un-minimize rather than close — history is preserved
      _minimized = false;
      document.getElementById('ss-chat-panel').classList.remove('ss-minimized');
      document.getElementById('ss-chat-input').focus();
      return;
    }
    _open = !_open;
    document.getElementById('ss-chat-panel').classList.toggle('d-none', !_open);
    if (_open && _msgs.length === 0) {
      _addMsg("Hi! I'm SmartShield AI. Ask me about your firewall rules, logs, active threats, connected devices, or any security question.", 'b');
    }
    if (_open) document.getElementById('ss-chat-input').focus();
  };

  window.ssChatMinimize = function() {
    _minimized = !_minimized;
    document.getElementById('ss-chat-panel').classList.toggle('ss-minimized', _minimized);
  };

  window.ssChatClear = function() {
    _msgs = [];
    document.getElementById('ss-chat-messages').innerHTML = '';
    _addMsg("Conversation cleared. How can I help?", 'b');
  };

  window.ssChatSend = async function() {
    const inp  = document.getElementById('ss-chat-input');
    const text = (inp.value || '').trim();
    if (!text) return;
    inp.value = '';

    _addMsg(text, 'u');
    _msgs.push({role:'user', content: text});

    const box = document.getElementById('ss-chat-messages');
    const thinking = document.createElement('div');
    thinking.className = 'ss-thinking';
    thinking.textContent = 'SmartShield AI is thinking…';
    box.appendChild(thinking);
    thinking.scrollIntoView({behavior:'smooth', block:'end'});

    const sendBtn = document.getElementById('ss-chat-send');
    sendBtn.disabled = true;

    try {
      const res = await fetch('/chatbot/api/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({messages: _msgs}),
      });
      thinking.remove();

      let data;
      try {
        data = await res.json();
      } catch(_) {
        if (res.status === 401 || res.redirected) {
          _addMsg('⚠ Session expired. Please refresh the page and log in again.', 's');
        } else {
          _addMsg('⚠ Server error (HTTP ' + res.status + '). Please try again.', 's');
        }
        return;
      }

      if (data.ok) {
        _msgs = data.messages;
        _addMsg(data.reply, 'b');
        if (data.pending_action) {
          _addActionCard(data.pending_action);
        }
      } else {
        _addMsg('⚠ ' + (data.message || 'Unknown error'), 's');
      }
    } catch(e) {
      thinking.remove();
      _addMsg('⚠ Could not reach the server. Check your connection and try again.', 's');
    } finally {
      sendBtn.disabled = false;
      inp.focus();
    }
  };
})();
