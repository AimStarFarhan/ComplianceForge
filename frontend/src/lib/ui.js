export function scoreColor(pct) {
  if (pct === null || pct === undefined) return "var(--ink-soft)";
  if (pct >= 80) return "var(--pass)";
  if (pct >= 50) return "var(--warn)";
  return "var(--fail)";
}

export function timeAgo(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
