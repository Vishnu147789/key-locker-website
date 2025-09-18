// Admin panel functionality

document.addEventListener('DOMContentLoaded', () => {
  // Real-time stats update
  function updateStats() {
    fetch('/admin/api/stats')
      .then(response => response.json())
      .then(data => {
        document.getElementById('totalUsers').textContent = data.users;
        document.getElementById('totalKeys').textContent = data.keys;
        document.getElementById('activeSessionsToday').textContent = data.sessions;
        document.getElementById('failedLoginsToday').textContent = data.failed_logins;
      })
      .catch(error => console.error('Failed to update stats:', error));
  }

  // Load audit logs
  function loadAuditLogs(page = 1) {
    fetch(`/admin/api/audit-logs?page=${page}`)
      .then(response => response.json())
      .then(data => {
        const container = document.getElementById('auditLogs');
        container.innerHTML = '';
        
        data.logs.forEach(log => {
          const item = document.createElement('div');
          item.className = 'audit-log-item';
          item.innerHTML = `
            <div class="audit-timestamp">${formatTimestamp(log.timestamp)}</div>
            <div class="audit-action">${log.action}</div>
            <div class="audit-details">User: ${log.username || 'System'} | IP: ${log.ip_address || 'N/A'}</div>
            ${log.details ? `<div class="audit-details">${log.details}</div>` : ''}
          `;
          container.appendChild(item);
        });
      })
      .catch(error => console.error('Failed to load audit logs:', error));
  }

  // Format timestamp for display
  function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
  }

  // User management functions
  function toggleUserStatus(username, action) {
    if (!confirm(`${action} user ${username}?`)) return;

    fetch(`/admin/api/users/${username}/${action}`, { method: 'POST' })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          location.reload();
        } else {
          alert(`Failed to ${action} user: ${data.error}`);
        }
      })
      .catch(error => {
        console.error(`Failed to ${action} user:`, error);
        alert(`Failed to ${action} user`);
      });
  }

  // Attach event listeners
  document.querySelectorAll('.disable-user-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const username = e.target.dataset.username;
      toggleUserStatus(username, 'disable');
    });
  });

  document.querySelectorAll('.enable-user-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const username = e.target.dataset.username;
      toggleUserStatus(username, 'enable');
    });
  });

  // Auto-update stats every 30 seconds
  setInterval(updateStats, 30000);

  // Load initial data
  updateStats();
  if (document.getElementById('auditLogs')) {
    loadAuditLogs();
  }
});
