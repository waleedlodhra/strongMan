$(document).ready(function () {
    $("[id^=toggle_connection]").on('click', handler);
});

function handler(event) {
    event.preventDefault();
    var connectionId = this.id.value;
    var csrf = this.csrfmiddlewaretoken.value;
    $.ajax({
        data: $(this).serialize(),
        type: 'POST',
        url: '/server_connections/toggle/',
        success: function (response) {
            if (!response.success) {
                setAlert(response);
                stateDown(response.id);
            }
        }
    });
    stateConnecting(connectionId);
    setTimeout(function () {
        getState(connectionId, csrf);
    }, 900);
    return false;
}

function stateEstablished(connectionId) {
    $('#toggle_input' + connectionId).prop('checked', true).change();
    var button = $('#button_div' + connectionId);
    button.find('.toggle-on').text("On");
    button.find('.toggle-on').attr("class", "btn btn-success toggle-on");
    button.find('.toggle').attr("class", 'toggle btn btn-success');
}

function stateDown(connectionId) {
    $('#toggle_input' + connectionId).prop('checked', false).change();
    var button = $('#button_div' + connectionId);
    button.find('.toggle-off').text("Off");
    $('#toggle_connection' + connectionId).prop('checked', false).change();
    button.find('.toggle').attr("class", 'toggle btn btn-default off');
}

function stateConnecting(connectionId) {
    var button = $('#button_div' + connectionId);
    button.find('.toggle-on').text("");
    button.find('.toggle-on').append("<i class='glyphicon glyphicon-refresh spinning'></i>");
    button.find('.toggle-on').attr("class", "btn btn-warning toggle-on");
    button.find('.toggle').attr("class", 'toggle btn btn-warning');
    $('#toggle_input' + connectionId).prop('checked', true).change();
    lock(connectionId);
}

function stateLoaded(connectionId) {
    var button = $('#button_div' + connectionId);
    button.find('.toggle-on').text("Loaded");
    button.find('.toggle-on').attr("class", "btn btn-success toggle-on");
    button.find('.toggle').attr("class", 'toggle btn btn-success');
    $('#toggle_input' + connectionId).prop('checked', true).change();
}

function stateUnloaded(connectionId) {
    var button = $('#button_div' + connectionId);
    button.find('.toggle-off').text("Unloaded");
    $('#toggle_connection' + connectionId).prop('checked', false).change();
    button.find('.toggle').attr("class", 'toggle btn btn-default off');
    $('#toggle_input' + connectionId).prop('checked', false).change();
}

function lock(connectionId) {
    $('#toggle_connection' + connectionId).unbind('click');
    setTimeout(function () { unlock(connectionId); }, 1000);
}

function unlock(connectionId) {
    $('#toggle_connection' + connectionId).on('click', handler);
}

function getState(connectionId, csrf) {
    $.ajax({
        data: {'csrfmiddlewaretoken': csrf},
        type: 'POST',
        url: '/server_connections/state/' + connectionId + '/',
        success: function (response) {
            if (response.success) {
                switch (response.state) {
                    case 'CONNECTING':
                        stateConnecting(response.id);
                        hideConnectionInfoRow(response.id);
                        setTimeout(function () { getState(connectionId, csrf); }, 900);
                        break;
                    case 'ESTABLISHED':
                        stateEstablished(response.id);
                        showConnectionInfoRow(response.id, csrf);
                        break;
                    case 'LOADED':
                        stateLoaded(response.id);
                        showConnectionInfoRow(response.id, csrf);
                        break;
                    case 'UNLOADED':
                        stateUnloaded(response.id);
                        hideConnectionInfoRow(response.id, csrf);
                        break;
                    default:
                        stateDown(response.id);
                        hideConnectionInfoRow(response.id);
                        break;
                }
            } else {
                setAlert(response);
                stateDown(response.id);
            }
        }
    });
}

function setAlert(response) {
    var alert = $('#alert_' + response.id);
    alert.popover({title: "Warning!", content: response.message, placement: "left", trigger: 'focus', container: 'body'});
    alert.popover('show');
}

function setConnectionInfo(connectionId, csrf) {
    $.ajax({
        data: {'csrfmiddlewaretoken': csrf, 'id': connectionId},
        type: 'POST',
        url: '/server_connections/info/',
        success: function (response) {
            if (response.success && $('#filter-active-status').val() === "0") {
                fillConnectionInfo(connectionId, response.child);
            }
            setTimeout(function () { setConnectionInfo(connectionId, csrf); }, 10000);
        }
    });
}

// ── helpers ──────────────────────────────────────────────────────────────────

function formatBytes(n) {
    n = parseInt(n, 10);
    if (isNaN(n)) return '0 B';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
}

function formatSeconds(s) {
    s = parseInt(s, 10);
    if (isNaN(s) || s <= 0) return '—';
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    var sec = s % 60;
    if (h > 0) return h + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + sec + 's';
    return sec + 's';
}

function stateBadge(state) {
    var cls = 'default';
    if (state === 'ESTABLISHED' || state === 'INSTALLED') cls = 'success';
    else if (state === 'CONNECTING' || state === 'REKEYING') cls = 'warning';
    else if (state === 'DELETING' || state === 'DESTROYING') cls = 'danger';
    return '<span class="label label-' + cls + '">' + (state || '?') + '</span>';
}

function makeTd(content, cls) {
    var el = document.createElement('td');
    if (cls) el.className = cls;
    if (typeof content === 'string' && content.indexOf('<') !== -1) {
        el.innerHTML = content;
    } else {
        el.appendChild(document.createTextNode(content));
    }
    return el;
}

function terminateForm(formId, saField, saValue, connId, btnId, onSubmitFn) {
    var form = document.createElement('form');
    form.id = formId;
    form.method = 'POST';
    form.action = '/server_connections/terminate_sa/';
    form.className = 'pull-right inline-class';
    form.setAttribute('onSubmit', 'return ' + onSubmitFn + '(this)');

    function hidden(name, val) {
        var inp = document.createElement('input');
        inp.type = 'hidden'; inp.name = name; inp.value = val;
        form.appendChild(inp);
    }
    hidden('csrfmiddlewaretoken', getCookie('csrftoken'));
    hidden(saField, saValue);
    hidden('conn_id', connId);

    var btn = document.createElement('button');
    btn.type = 'submit';
    btn.className = 'btn btn-default btn-sm';
    btn.id = btnId;
    btn.innerHTML = '<span class="glyphicon glyphicon-remove"></span><span id="' + btnId + '_text"></span>';
    form.appendChild(btn);
    return form;
}

// ─────────────────────────────────────────────────────────────────────────────

function fillConnectionInfo(id, child) {
    fillInfos(id, Object.keys(child).length, child);
}

function showConnectionInfoRow(id, csrf) {
    setConnectionInfo(id, csrf);
    $('#connection-info-row-' + id).toggle(true);
    $('#connection-row-' + id).addClass("success");
    var btn = $('#collapse-btn-' + id);
    var btn_text = btn.children().slice(0);
    if (btn_text.hasClass("glyphicon-chevron-right")) {
        btn_text.removeClass("glyphicon-chevron-right");
        btn_text.addClass("glyphicon-chevron-down");
    }
}

function hideConnectionInfoRow(id) {
    $('#connection-info-row-' + id).toggle(false);
    $('#connection-row-' + id).removeClass("success");
    var btn = $('#collapse-btn-' + id);
    var btn_text = btn.children().slice(0);
    if (btn_text.hasClass("glyphicon-chevron-down")) {
        btn_text.removeClass("glyphicon-chevron-down");
        btn_text.addClass("glyphicon-chevron-right");
    }
}

function toggleConnectionInfoRow(id) {
    var row = $('#connection-info-row-' + id);
    var btn = $('#collapse-btn-' + id);
    var btn_text = btn.children().slice(0);
    if (btn_text.hasClass("glyphicon-chevron-right")) {
        btn_text.removeClass("glyphicon-chevron-right");
        btn_text.addClass("glyphicon-chevron-down");
    } else {
        btn_text.removeClass("glyphicon-chevron-down");
        btn_text.addClass("glyphicon-chevron-right");
    }
    row.toggle();
}

function fillInfos(conn_id, rows, child) {
    var sas = document.getElementById('connection-' + conn_id + '-sas');
    $('#connection-' + conn_id + '-sas tr').remove();

    for (var i = 0; i < rows; i++) {
        var ike = child[i];
        var id  = ike.uniqueid;
        var encr = (ike.encr_alg || '') + (ike.encr_keysize ? '/' + ike.encr_keysize : '');

        // ── IKE SA row ───────────────────────────────────────────────────────
        var row = document.createElement('tr');
        row.appendChild(makeTd(ike.remote_host || '—'));
        row.appendChild(makeTd(ike.remote_id   || '—'));
        row.appendChild(makeTd(stateBadge(ike.state)));
        row.appendChild(makeTd('IKEv' + (ike.version || '?') + (encr ? ' · ' + encr : '')));
        row.appendChild(makeTd(formatSeconds(ike.established) + ' ago'));
        row.appendChild(makeTd('reauth ' + formatSeconds(ike.reauth_time)));

        var terminate_td = document.createElement('td');
        terminate_td.appendChild(terminateForm(
            id, 'sa_id', id, conn_id,
            'btn_terminate_sa_' + id, 'button_terminate_sa_clicked'
        ));
        row.appendChild(terminate_td);
        sas.appendChild(row);

        // ── Child SA sub-table ───────────────────────────────────────────────
        var child_sas = ike.child_sas;
        var nr = Object.keys(child_sas).length;
        if (nr === 0) continue;

        var csa_row = document.createElement('tr');
        csa_row.id = 'child_sas' + id;

        var csa_cell = document.createElement('td');
        csa_cell.className = 'child-sa-cell';
        csa_cell.colSpan = '7';
        csa_cell.style.cssText = 'padding-left:34px; background-color:#dadfe8;';

        var tbl = document.createElement('table');
        tbl.className = 'table-hover table-condensed table-responsive child-sa-table';
        tbl.style.width = '100%';

        var thead = document.createElement('thead');
        thead.innerHTML = '<tr><th>Name</th><th>State</th><th>Local TS</th><th>Remote TS</th>' +
            '<th>Bytes In</th><th>Bytes Out</th><th>Pkts In</th><th>Pkts Out</th>' +
            '<th>Installed</th><th>Rekey in</th><th></th></tr>';
        tbl.appendChild(thead);

        var tbody = document.createElement('tbody');
        for (var n = 0; n < nr; n++) {
            var cs  = child_sas[n];
            var cid = cs.uniqueid;
            var cr  = document.createElement('tr');

            cr.appendChild(makeTd(cs.name    || '—',  'child-sa-cell'));
            cr.appendChild(makeTd(stateBadge(cs.state), 'child-sa-cell'));
            cr.appendChild(makeTd(cs.local_ts  || '—', 'child-sa-cell'));
            cr.appendChild(makeTd(cs.remote_ts || '—', 'child-sa-cell'));
            cr.appendChild(makeTd(formatBytes(cs.bytes_in),  'child-sa-cell'));
            cr.appendChild(makeTd(formatBytes(cs.bytes_out), 'child-sa-cell'));
            cr.appendChild(makeTd(cs.packets_in  || '0', 'child-sa-cell'));
            cr.appendChild(makeTd(cs.packets_out || '0', 'child-sa-cell'));
            cr.appendChild(makeTd(formatSeconds(cs.install_time) + ' ago', 'child-sa-cell'));
            cr.appendChild(makeTd(formatSeconds(cs.rekey_time),  'child-sa-cell'));

            var ctd = document.createElement('td');
            ctd.className = 'child-sa-cell';
            ctd.appendChild(terminateForm(
                cid, 'child_sa_id', cid, conn_id,
                'btn_terminate_child_sa_' + cid, 'button_terminate_child_sa_clicked'
            ));
            cr.appendChild(ctd);
            tbody.appendChild(cr);
        }
        tbl.appendChild(tbody);
        csa_cell.appendChild(tbl);
        csa_row.appendChild(csa_cell);
        sas.appendChild(csa_row);
    }
}

function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) === ' ') { c = c.substring(1); }
        if (c.indexOf(name) === 0) { return c.substring(name.length, c.length); }
    }
    return "";
}

button_terminate_sa_clicked = function (form) {
    var btn = $("#btn_terminate_sa_" + form.id);
    if (btn.hasClass('btn-default')) {
        btn.removeClass('btn-default').addClass('btn-danger');
        btn.children('#btn_terminate_sa_' + form.id + '_text').text(' terminate');
        return false;
    }
    return true;
};

button_terminate_child_sa_clicked = function (form) {
    var btn = $("#btn_terminate_child_sa_" + form.id);
    if (btn.hasClass('btn-default')) {
        btn.removeClass('btn-default').addClass('btn-danger');
        btn.children('#btn_terminate_child_sa_' + form.id + '_text').text(' terminate');
        return false;
    }
    return true;
};
