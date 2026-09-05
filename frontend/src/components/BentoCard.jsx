import { scoreColor } from "../lib/ui";

/** Big severity bento card, e.g. "01 / Telnet VTY Cleartext Access". */
export default function BentoCard({ label, icon, digit, title, sub, accent, progress, wash }) {
  return (
    <div className="bg-warm-sandstone border border-weathered-taupe p-4 rounded-lg shadow-sm flex flex-col justify-between">
      <div className="flex items-center justify-between text-taupe-muted">
        <span className="font-mono text-[10px] uppercase tracking-wider font-semibold">{label}</span>
        <span className="material-symbols-outlined text-[20px]" style={{ color: accent }}>{icon}</span>
      </div>
      <div className="my-2">
        {digit && (
          <div className="font-display text-3xl font-bold leading-none" style={{ color: accent }}>
            {digit}
          </div>
        )}
        {!digit && <div className="font-display text-lg font-bold text-peatCharcoal">{title}</div>}
        <div className="font-sans text-xs text-peatCharcoal font-medium mt-1">{digit ? title : sub}</div>
        {digit && sub && <div className="font-mono text-[11px] text-taupe-muted mt-0.5">{sub}</div>}
      </div>
      {progress !== undefined && (
        <div className="h-1.5 w-full bg-creamParchment rounded-full overflow-hidden border border-weathered-taupe/60">
          <div className="h-full rounded-full" style={{ width: `${progress}%`, background: accent }}></div>
        </div>
      )}
    </div>
  );
}

/** Circular compliance gauge as in the reference (SVG ring). */
export function ScoreGauge({ pct, size = 52 }) {
  const r = (size - 9) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - (pct || 0) / 100);
  const color = (pct ?? 0) >= 80 ? "#2D6A4F" : (pct ?? 0) >= 50 ? "#C27803" : "#B84A39";
  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} fill="none" r={r} stroke="#D6D0C4" strokeWidth="4.5" />
        <circle
          cx={size / 2}
          cy={size / 2}
          fill="none"
          r={r}
          stroke={color}
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          strokeWidth="4.5"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="font-display text-base font-bold text-peatCharcoal leading-none">
          {pct !== null && pct !== undefined ? Math.round(pct) : "—"}
        </span>
      </div>
    </div>
  );
}
