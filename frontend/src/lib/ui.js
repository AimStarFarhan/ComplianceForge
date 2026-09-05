export function scoreColor(pct) {
  if (pct === null || pct === undefined) return "#726F67";
  if (pct >= 80) return "#2D6A4F";
  if (pct >= 50) return "#C27803";
  return "#B84A39";
}

export function timeAgo(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
