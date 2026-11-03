/**
 * NIDS Monitor – main.js
 * Global scripts: flash dismiss, responsive sidebar
 */

// ── Auto-dismiss Flash Messages ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // Dismiss flash after 4 seconds
  setTimeout(() => {
    document.querySelectorAll('.flash').forEach(el => {
      el.style.transition = 'opacity 0.4s, transform 0.4s';
      el.style.opacity = '0';
      el.style.transform = 'translateX(40px)';
      setTimeout(() => el.remove(), 400);
    });
  }, 4000);

  // Click to dismiss immediately
  document.querySelectorAll('.flash').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', () => {
      el.style.transition = 'opacity 0.2s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 200);
    });
  });

  // ── Mobile Sidebar Toggle ───────────────────────────────────────────────
  const sidebar = document.getElementById('sidebar');
  if (sidebar) {
    // Create hamburger if on mobile
    if (window.innerWidth <= 768) {
      const burger = document.createElement('button');
      burger.innerHTML = '☰';
      burger.style.cssText = `
        position:fixed;top:14px;left:14px;z-index:200;
        background:rgba(108,99,255,0.9);color:#fff;
        border:none;border-radius:8px;padding:8px 12px;
        font-size:18px;cursor:pointer;backdrop-filter:blur(10px);`;
      burger.id = 'sidebar-toggle';
      document.body.appendChild(burger);

      burger.addEventListener('click', () => {
        const open = sidebar.style.transform === 'translateX(0px)';
        sidebar.style.transform = open ? 'translateX(-100%)' : 'translateX(0px)';
        burger.innerHTML = open ? '☰' : '✕';
      });
    }
  }

  // ── Confirm Dangerous Actions ───────────────────────────────────────────
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', (e) => {
      if (!confirm(el.dataset.confirm)) e.preventDefault();
    });
  });

  // ── Highlight active nav based on URL hash ──────────────────────────────
  const hash = window.location.hash;
  if (hash) {
    const target = document.querySelector(hash);
    if (target) {
      setTimeout(() => {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 200);
    }
  }

});

// ── Format number with commas ─────────────────────────────────────────────
function formatNumber(n) {
  return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.');
}

// ── Relative time ─────────────────────────────────────────────────────────
function relativeTime(isoString) {
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000);
  if (diff < 60)   return `${diff}d lalu`;
  if (diff < 3600) return `${Math.floor(diff/60)}m lalu`;
  if (diff < 86400) return `${Math.floor(diff/3600)}j lalu`;
  return `${Math.floor(diff/86400)}h lalu`;
}
