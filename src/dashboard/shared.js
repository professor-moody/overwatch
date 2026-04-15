// ============================================================
// Overwatch Dashboard — Shared Utilities
// Common helpers used by both operator and graph pages
// ============================================================

window.OverwatchShared = {
  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },

  formatTime(timestamp) {
    if (!timestamp) return '';
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch { return ''; }
  },

  formatRelativeTime(timestamp) {
    if (!timestamp) return '';
    try {
      const diff = Date.now() - new Date(timestamp).getTime();
      if (diff < 60000) return 'just now';
      if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
      if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
      return Math.floor(diff / 86400000) + 'd ago';
    } catch { return ''; }
  },

  setBadge(state, label) {
    const badge = document.getElementById('ws-status');
    if (!badge) return;
    badge.className = 'status-badge' + (state ? ' ' + state : '');
    badge.innerHTML = '<span class="status-dot"></span><span>' + label + '</span>';
  },
};
