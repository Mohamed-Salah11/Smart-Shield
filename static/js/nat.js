/*
 * nat.js — Smart Shield NAT rules UI (port forward / 1:1 / outbound / NPt).
 *
 * Tabbed CRUD for the four NAT rule types, wired to /firewall/api/nat/<type>.
 * Each tab loads on page-ready, modal Save/Edit/Delete buttons call the
 * corresponding endpoint, and a single per-type editingNatId state determines
 * POST (add) vs PUT (edit). The auto-generated handler registry in
 * <!-- inline-handlers:auto --> below stays inline because scripts/migrate_handlers.py
 * regenerates it from the templates' data-action attributes.
 */

// --- TAB SWITCHING FUNCTION ---
function openTab(evt, tabName) {
    evt.preventDefault();
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.nav-tabs .nav-link').forEach(l => l.classList.remove('active'));
    document.getElementById('tab-' + tabName).classList.add('active');
    evt.currentTarget.classList.add('active');
}

// --- HELPER VARIABLES ---
const pfTbody = document.getElementById('pf-tbody');
const oneToOneTbody = document.getElementById('1to1-tbody');
const outboundTbody = document.getElementById('outbound-tbody');
const nptTbody = document.getElementById('npt-tbody');

let pfAddPosition = 'bottom';
let oneToOneAddPosition = 'bottom';
let outboundAddPosition = 'bottom';
let nptAddPosition = 'bottom';

document.getElementById('pfModal').addEventListener('show.bs.modal', function(event) {
    const button = event.relatedTarget;
    if (button) {
        pfAddPosition = button.getAttribute('data-position') || 'bottom';
    }
});

document.getElementById('oneToOneModal').addEventListener('show.bs.modal', function(event) {
    const button = event.relatedTarget;
    if (button) {
        oneToOneAddPosition = button.getAttribute('data-position') || 'bottom';
    }
});

document.getElementById('outboundModal').addEventListener('show.bs.modal', function(event) {
    const button = event.relatedTarget;
    if (button) {
        outboundAddPosition = button.getAttribute('data-position') || 'bottom';
    }
});

document.getElementById('nptModal').addEventListener('show.bs.modal', function(event) {
    const button = event.relatedTarget;
    if (button) {
        nptAddPosition = button.getAttribute('data-position') || 'bottom';
    }
});

// --- MOVE NAT RULE FUNCTION ---
async function moveNatRule(type, ruleId, direction) {
    try {
        const response = await fetch(`/firewall/api/nat/${type}/${ruleId}/move`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ direction: direction })
        });
        const result = await response.json();
        if (result.success) {
            if (type === 'pf') loadPortForwardRules();
            else if (type === '1to1') load1to1Rules();
            else if (type === 'outbound') loadOutboundRules();
            else if (type === 'npt') loadNptRules();
        } else {
            alert('Error moving rule: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error moving rule:', error);
        alert('Could not move rule');
    }
}

// Tracks which record is being edited per NAT type (null = add mode)
const editingNatId = { pf: null, '1to1': null, outbound: null, npt: null };

async function saveNatRule(type, ruleData, modal, formId, reloadFn) {
    const editing  = editingNatId[type];
    const endpoint = `/firewall/api/nat/${type}` + (editing ? `/${editing}` : '');
    const method   = editing ? 'PUT' : 'POST';
    try {
        const response = await fetch(endpoint, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(ruleData)
        });
        const result = await response.json();
        if (result.success) {
            editingNatId[type] = null;
            bootstrap.Modal.getInstance(modal).hide();
            if (formId) document.getElementById(formId).reset();
            reloadFn();
        } else {
            alert('Error saving rule: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Could not connect to the backend server.');
    }
}

// --- PORT FORWARD SAVE ---
const pfModal = document.getElementById('pfModal');
document.getElementById('pfRuleSaveBtn').addEventListener('click', async () => {
    const ruleData = {
        disabled: document.getElementById('pf_disabled').checked ? 1 : 0,
        interface: document.getElementById('pf_interface').value,
        protocol: document.getElementById('pf_protocol').value,
        src_type: document.getElementById('pf_src_type').value,
        src_address: document.getElementById('pf_src_address').value || '',
        dst_type: document.getElementById('pf_dst_type').value,
        dst_address: document.getElementById('pf_dst_address').value || '',
        dst_port: document.getElementById('pf_dst_port').value || '',
        redirect_ip: document.getElementById('pf_redirect_ip').value || '',
        redirect_port: document.getElementById('pf_redirect_port').value || '',
        description: document.getElementById('pf_description').value || 'New port forward rule',
        nat_reflection: document.getElementById('pf_nat_reflection').value,
        position: pfAddPosition
    };
    await saveNatRule('pf', ruleData, pfModal, 'pfRuleForm', loadPortForwardRules);
});

// --- 1:1 NAT SAVE ---
const oneToOneModal = document.getElementById('oneToOneModal');
document.getElementById('1to1RuleSaveBtn').addEventListener('click', async () => {
    const ruleData = {
        disabled: document.getElementById('1to1_disabled').checked ? 1 : 0,
        interface: document.getElementById('1to1_interface').value,
        external_address: document.getElementById('1to1_external_address').value || '',
        internal_address: document.getElementById('1to1_internal_address').value || '',
        destination_address: 'any',
        description: document.getElementById('1to1_description').value || 'New 1:1 NAT mapping',
        position: oneToOneAddPosition
    };
    await saveNatRule('1to1', ruleData, oneToOneModal, 'oneToOneRuleForm', load1to1Rules);
});

// --- OUTBOUND NAT SAVE ---
const outboundModal = document.getElementById('outboundModal');
document.getElementById('outboundRuleSaveBtn').addEventListener('click', async () => {
    const ruleData = {
        disabled: document.getElementById('outbound_disabled').checked ? 1 : 0,
        interface: document.getElementById('outbound_interface').value,
        protocol: document.getElementById('outbound_protocol').value,
        src_address: document.getElementById('outbound_src_address').value || '',
        dst_address: document.getElementById('outbound_dst_address').value || 'any',
        static_port: document.getElementById('outbound_static_port').checked ? 1 : 0,
        description: document.getElementById('outbound_description').value || 'New outbound NAT rule',
        position: outboundAddPosition
    };
    await saveNatRule('outbound', ruleData, outboundModal, 'outboundRuleForm', loadOutboundRules);
});

// --- NPt SAVE ---
const nptModal = document.getElementById('nptModal');
document.getElementById('nptRuleSaveBtn').addEventListener('click', async () => {
    const ruleData = {
        disabled: document.getElementById('npt_disabled').checked ? 1 : 0,
        interface: document.getElementById('npt_interface').value,
        src_prefix: document.getElementById('npt_src_prefix').value || 'fd00::/64',
        dst_prefix: document.getElementById('npt_dst_prefix').value || '2001:db8::/64',
        description: document.getElementById('npt_description').value || 'New NPt mapping',
        position: nptAddPosition
    };
    await saveNatRule('npt', ruleData, nptModal, 'nptRuleForm', loadNptRules);
});

// --- DELETE BUTTONS ---
document.getElementById('pf-delete-btn').addEventListener('click', async () => {
    const checkboxes = pfTbody.querySelectorAll('input[type="checkbox"]:checked');
    if (checkboxes.length === 0) {
        alert('Please select at least one rule to delete');
        return;
    }
    if (confirm(`Are you sure you want to delete ${checkboxes.length} rule(s)?`)) {
        for (const checkbox of checkboxes) {
            const row = checkbox.closest('tr');
            const ruleId = row.dataset.ruleId;
            if (ruleId) {
                await fetch(`/firewall/api/nat/pf/${ruleId}`, { method: 'DELETE' });
            }
        }
        loadPortForwardRules();
    }
});

document.getElementById('1to1-delete-btn').addEventListener('click', async () => {
    const checkboxes = oneToOneTbody.querySelectorAll('input[type="checkbox"]:checked');
    if (checkboxes.length === 0) {
        alert('Please select at least one mapping to delete');
        return;
    }
    if (confirm(`Are you sure you want to delete ${checkboxes.length} mapping(s)?`)) {
        for (const checkbox of checkboxes) {
            const row = checkbox.closest('tr');
            const ruleId = row.dataset.ruleId;
            if (ruleId) {
                await fetch(`/firewall/api/nat/1to1/${ruleId}`, { method: 'DELETE' });
            }
        }
        load1to1Rules();
    }
});

document.getElementById('outbound-delete-btn').addEventListener('click', async () => {
    const checkboxes = outboundTbody.querySelectorAll('input[type="checkbox"]:checked');
    if (checkboxes.length === 0) {
        alert('Please select at least one mapping to delete');
        return;
    }
    if (confirm(`Are you sure you want to delete ${checkboxes.length} mapping(s)?`)) {
        for (const checkbox of checkboxes) {
            const row = checkbox.closest('tr');
            const ruleId = row.dataset.ruleId;
            if (ruleId) {
                await fetch(`/firewall/api/nat/outbound/${ruleId}`, { method: 'DELETE' });
            }
        }
        loadOutboundRules();
    }
});

document.getElementById('npt-delete-btn').addEventListener('click', async () => {
    const checkboxes = nptTbody.querySelectorAll('input[type="checkbox"]:checked');
    if (checkboxes.length === 0) {
        alert('Please select at least one mapping to delete');
        return;
    }
    if (confirm(`Are you sure you want to delete ${checkboxes.length} mapping(s)?`)) {
        for (const checkbox of checkboxes) {
            const row = checkbox.closest('tr');
            const ruleId = row.dataset.ruleId;
            if (ruleId) {
                await fetch(`/firewall/api/nat/npt/${ruleId}`, { method: 'DELETE' });
            }
        }
        loadNptRules();
    }
});

// --- LOAD EXISTING NAT RULES FROM DATABASE ---
async function loadPortForwardRules() {
    try {
        const response = await fetch('/firewall/api/nat/pf');
        const result = await response.json();
        if (result.success && result.rules) {
            pfTbody.innerHTML = '';
            result.rules.forEach(rule => {
                const row = document.createElement('tr');
                row.dataset.ruleId = rule.id;
                row.innerHTML = `
                    <td><input type="checkbox"></td>
                    <td>${rule.interface || 'WAN'}</td>
                    <td>${rule.protocol || 'TCP'}</td>
                    <td>${rule.src_address || '*'}</td>
                    <td>*</td>
                    <td>${rule.dst_address || 'WAN address'}</td>
                    <td>${rule.dst_port || '*'}</td>
                    <td>${rule.redirect_ip || ''}</td>
                    <td>${rule.redirect_port || '*'}</td>
                    <td>${rule.description || ''}</td>
                    <td>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="pf" data-id="${rule.id}" data-dir="up" title="Move Up"><i class="fas fa-arrow-up"></i></button>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="pf" data-id="${rule.id}" data-dir="down" title="Move Down"><i class="fas fa-arrow-down"></i></button>
                        <button type="button" class="btn btn-sm btn-primary" data-action="nat-edit" data-tab="pf" data-id="${rule.id}"><i class="fas fa-edit"></i></button>
                        <button type="button" class="btn btn-sm btn-danger" data-action="nat-delete" data-tab="pf" data-id="${rule.id}"><i class="fas fa-trash"></i></button>
                    </td>
                `;
                pfTbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading port forward rules:', error);
    }
}

async function load1to1Rules() {
    try {
        const response = await fetch('/firewall/api/nat/1to1');
        const result = await response.json();
        if (result.success && result.rules) {
            oneToOneTbody.innerHTML = '';
            result.rules.forEach(rule => {
                const row = document.createElement('tr');
                row.dataset.ruleId = rule.id;
                row.innerHTML = `
                    <td><input type="checkbox"></td>
                    <td>${rule.interface || 'WAN'}</td>
                    <td>${rule.external_address || ''}</td>
                    <td>${rule.internal_address || ''}</td>
                    <td>${rule.destination_address || '*'}</td>
                    <td>${rule.description || ''}</td>
                    <td>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="1to1" data-id="${rule.id}" data-dir="up" title="Move Up"><i class="fas fa-arrow-up"></i></button>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="1to1" data-id="${rule.id}" data-dir="down" title="Move Down"><i class="fas fa-arrow-down"></i></button>
                        <button type="button" class="btn btn-sm btn-primary" data-action="nat-edit" data-tab="1to1" data-id="${rule.id}"><i class="fas fa-edit"></i></button>
                        <button type="button" class="btn btn-sm btn-danger" data-action="nat-delete" data-tab="1to1" data-id="${rule.id}"><i class="fas fa-trash"></i></button>
                    </td>
                `;
                oneToOneTbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading 1:1 NAT rules:', error);
    }
}

async function loadOutboundRules() {
    try {
        const response = await fetch('/firewall/api/nat/outbound');
        const result = await response.json();
        if (result.success && result.rules) {
            outboundTbody.innerHTML = '';
            result.rules.forEach(rule => {
                const row = document.createElement('tr');
                row.dataset.ruleId = rule.id;
                row.innerHTML = `
                    <td><input type="checkbox"></td>
                    <td>${rule.interface || 'WAN'}</td>
                    <td>${rule.src_address || '*'}</td>
                    <td>*</td>
                    <td>*</td>
                    <td>${rule.dst_address || '*'}</td>
                    <td>${rule.nat_address || 'WAN address'}</td>
                    <td>*</td>
                    <td>${rule.static_port ? 'Yes' : 'No'}</td>
                    <td>${rule.description || ''}</td>
                    <td>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="outbound" data-id="${rule.id}" data-dir="up" title="Move Up"><i class="fas fa-arrow-up"></i></button>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="outbound" data-id="${rule.id}" data-dir="down" title="Move Down"><i class="fas fa-arrow-down"></i></button>
                        <button type="button" class="btn btn-sm btn-primary" data-action="nat-edit" data-tab="outbound" data-id="${rule.id}"><i class="fas fa-edit"></i></button>
                        <button type="button" class="btn btn-sm btn-danger" data-action="nat-delete" data-tab="outbound" data-id="${rule.id}"><i class="fas fa-trash"></i></button>
                    </td>
                `;
                outboundTbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading outbound NAT rules:', error);
    }
}

async function deleteNatRule(type, ruleId) {
    if (!confirm('Are you sure you want to delete this NAT rule?')) return;

    try {
        const response = await fetch(`/firewall/api/nat/${type}/${ruleId}`, {
            method: 'DELETE'
        });
        const result = await response.json();
        if (result.success) {
            alert('NAT rule deleted successfully!');
            if (type === 'pf') loadPortForwardRules();
            else if (type === '1to1') load1to1Rules();
            else if (type === 'outbound') loadOutboundRules();
            else if (type === 'npt') loadNptRules();
        } else {
            alert('Error deleting rule: ' + result.error);
        }
    } catch (error) {
        console.error('Error deleting NAT rule:', error);
        alert('Could not delete rule');
    }
}

async function editNatRule(type, ruleId) {
    try {
        const response = await fetch(`/firewall/api/nat/${type}/${ruleId}`);
        const result   = await response.json();
        if (!result.success) { alert('Could not load rule: ' + (result.error || '')); return; }
        const rule = result.rule;
        editingNatId[type] = ruleId;

        if (type === 'pf') {
            const modal = document.getElementById('pfModal');
            document.getElementById('pfModalLabel').textContent   = 'Edit Port Forward Rule';
            document.getElementById('pf_disabled').checked         = !!rule.disabled;
            document.getElementById('pf_interface').value          = rule.interface     || 'WAN';
            document.getElementById('pf_protocol').value           = rule.protocol      || 'tcp';
            document.getElementById('pf_src_type').value           = rule.src_type      || 'any';
            document.getElementById('pf_src_address').value        = rule.src_address   || '';
            document.getElementById('pf_dst_type').value           = rule.dst_type      || 'wan_address';
            document.getElementById('pf_dst_address').value        = rule.dst_address   || '';
            document.getElementById('pf_dst_port').value           = rule.dst_port      || '';
            document.getElementById('pf_redirect_ip').value        = rule.redirect_ip   || '';
            document.getElementById('pf_redirect_port').value      = rule.redirect_port || '';
            document.getElementById('pf_description').value        = rule.description   || '';
            document.getElementById('pf_nat_reflection').value     = rule.nat_reflection || 'default';
            new bootstrap.Modal(modal).show();

        } else if (type === '1to1') {
            const modal = document.getElementById('oneToOneModal');
            const titleEl = modal.querySelector('.modal-title');
            if (titleEl) titleEl.textContent = 'Edit 1:1 NAT Mapping';
            document.getElementById('1to1_disabled').checked          = !!rule.disabled;
            document.getElementById('1to1_interface').value           = rule.interface         || 'WAN';
            document.getElementById('1to1_external_address').value    = rule.external_address  || '';
            document.getElementById('1to1_internal_address').value    = rule.internal_address  || '';
            document.getElementById('1to1_description').value         = rule.description       || '';
            new bootstrap.Modal(modal).show();

        } else if (type === 'outbound') {
            const modal = document.getElementById('outboundModal');
            const titleEl = modal.querySelector('.modal-title');
            if (titleEl) titleEl.textContent = 'Edit Outbound NAT Rule';
            document.getElementById('outbound_disabled').checked     = !!rule.disabled;
            document.getElementById('outbound_interface').value      = rule.interface   || 'WAN';
            const protoEl = document.getElementById('outbound_protocol');
            if (protoEl) protoEl.value = rule.protocol || 'any';
            document.getElementById('outbound_src_address').value    = rule.src_address || '';
            document.getElementById('outbound_dst_address').value    = rule.dst_address || 'any';
            const spEl = document.getElementById('outbound_static_port');
            if (spEl) spEl.checked = !!rule.static_port;
            document.getElementById('outbound_description').value    = rule.description || '';
            new bootstrap.Modal(modal).show();

        } else if (type === 'npt') {
            const modal = document.getElementById('nptModal');
            const titleEl = modal.querySelector('.modal-title');
            if (titleEl) titleEl.textContent = 'Edit NPt Mapping';
            document.getElementById('npt_disabled').checked    = !!rule.disabled;
            document.getElementById('npt_interface').value     = rule.interface  || 'WAN';
            document.getElementById('npt_src_prefix').value    = rule.src_prefix || '';
            document.getElementById('npt_dst_prefix').value    = rule.dst_prefix || '';
            document.getElementById('npt_description').value   = rule.description || '';
            new bootstrap.Modal(modal).show();
        }
    } catch (e) {
        alert('Failed to load NAT rule for editing.');
    }
}

async function loadNptRules() {
    try {
        const response = await fetch('/firewall/api/nat/npt');
        const result = await response.json();
        if (result.success && result.rules) {
            nptTbody.innerHTML = '';
            result.rules.forEach(rule => {
                const row = document.createElement('tr');
                row.dataset.ruleId = rule.id;
                row.innerHTML = `
                    <td><input type="checkbox"></td>
                    <td>${rule.interface || 'WAN'}</td>
                    <td>${rule.src_prefix || ''}</td>
                    <td>${rule.dst_prefix || ''}</td>
                    <td>${rule.description || ''}</td>
                    <td>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="npt" data-id="${rule.id}" data-dir="up" title="Move Up"><i class="fas fa-arrow-up"></i></button>
                        <button type="button" class="btn btn-sm btn-secondary" data-action="nat-move" data-tab="npt" data-id="${rule.id}" data-dir="down" title="Move Down"><i class="fas fa-arrow-down"></i></button>
                        <button type="button" class="btn btn-sm btn-primary" data-action="nat-edit" data-tab="npt" data-id="${rule.id}"><i class="fas fa-edit"></i></button>
                        <button type="button" class="btn btn-sm btn-danger" data-action="nat-delete" data-tab="npt" data-id="${rule.id}"><i class="fas fa-trash"></i></button>
                    </td>
                `;
                nptTbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading NPt rules:', error);
    }
}

// ── Delegated row-action handlers (CSP-safe; rows are rendered here) ─────────
(function () {
    var R = window.SSActions || (window.SSActions = {});
    R['nat-move']   = function (event, el) { moveNatRule(el.dataset.tab, el.dataset.id, el.dataset.dir); };
    R['nat-edit']   = function (event, el) { editNatRule(el.dataset.tab, el.dataset.id); };
    R['nat-delete'] = function (event, el) { deleteNatRule(el.dataset.tab, el.dataset.id); };
})();

// Load all NAT rules on page load
loadPortForwardRules();
load1to1Rules();
loadOutboundRules();
loadNptRules();
