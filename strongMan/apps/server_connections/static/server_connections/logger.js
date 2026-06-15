var _logLastId   = -1;
var _logCsrf     = null;
var _logTimer    = null;
var _logPollMs   = 5000;   // poll every 5 seconds

function logger(csrf, logId) {
    _logCsrf   = csrf;
    _logLastId = (typeof logId !== 'undefined') ? logId : -1;
    _logPoll();
}

function _logPoll() {
    $.ajax({
        data: { csrfmiddlewaretoken: _logCsrf, id: _logLastId },
        type: 'POST',
        url:  '/server_connections/log/',
        timeout: 10000,
        success: function (response) {
            var logs = response.logs || [];
            logs.forEach(function (log) {
                addRowToLog(log);
                _logLastId = log.id;
            });
            _updateLogEmptyState();
        },
        error: function () { /* silent — retry next poll */ },
        complete: function () {
            _logTimer = setTimeout(_logPoll, _logPollMs);
        }
    });
}

function addRowToLog(log) {
    $('#log_table tbody').append(
        '<tr class="child">' +
        '<td class="timestamp">' + log.timestamp + '</td>' +
        '<td class="con_name">' + log.name + '</td>' +
        '<td><p>' + log.message + '</p></td>' +
        '</tr>'
    );
    $('#log-content').scrollTop($('#log_table').height());
    // auto-expand the log panel when logs arrive
    if ($('#collapse1').hasClass('in') === false) {
        $('#collapse1').addClass('in');
    }
}

function _updateLogEmptyState() {
    var hasRows = $('#log_table tbody tr').length > 0;
    if (hasRows) {
        $('#log-empty-state').hide();
    } else {
        $('#log-empty-state').show();
    }
}

$(document).ready(function () {
    $('#log_panel').on('shown.bs.collapse', function () {
        $('#log-content').scrollTop($('#log_table').height());
    });
});
