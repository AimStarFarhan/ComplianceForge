import Logo from "./Logo";

/**
 * Cold-start overlay. On deployed backends (serverless) the first /health
 * can take a minute — this shows branded skeleton charts with live status
 * instead of an error, and polls until the API answers.
 */
const BARS = [42, 68, 55, 82, 61, 90, 74, 50, 66, 80, 58, 72];

export default function WarmupSplash({ attempt, elapsed, failed, onRetry, onContinue }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-6" style={{ background: "var(--paper)" }}>
      <div className="w-full max-w-2xl card p-8 m-fade-up">
        <div className="flex items-center gap-3">
          <Logo className="h-10 w-10 rounded-lg" />
          <div>
            <div className="font-display text-lg font-bold">ComplianceForge</div>
            <div className="font-mono text-[11px]" style={{ color: "var(--ink-soft)" }}>
              {failed ? "BACKEND UNREACHABLE" : "WAKING UP THE BACKEND…"}
            </div>
          </div>
          <span className="flex-1" />
          <span className="font-mono text-[11px]" style={{ color: "var(--ink-soft)" }}>
            attempt {attempt} · {elapsed}s
          </span>
        </div>

        {/* skeleton charts — shimmer while the real fleet data loads */}
        <div className="grid grid-cols-3 gap-3 mt-6">
          {["FLEET SCORE", "DEVICES", "OPEN FINDINGS"].map((l) => (
            <div key={l} className="pane p-3">
              <div className="label-xs">{l}</div>
              <div className="skeleton-bar mt-2 h-7 w-2/3 rounded" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-5 gap-3 mt-3">
          <div className="pane p-3 col-span-3">
            <div className="label-xs mb-2">COMPLIANCE BY DEVICE</div>
            <div className="flex items-end gap-1.5 h-24">
              {BARS.map((h, i) => (
                <div
                  key={i}
                  className="skeleton-bargrow flex-1 rounded-t"
                  style={{ animationDelay: `${i * 120}ms`, ["--bar-h"]: `${h}%` }}
                />
              ))}
            </div>
          </div>
          <div className="pane p-3 col-span-2 flex flex-col items-center justify-center gap-2">
            <div className="label-xs">FLEET POSTURE</div>
            <svg width="84" height="84" viewBox="0 0 84 84" className="skeleton-donut">
              <circle cx="42" cy="42" r="32" fill="none" strokeWidth="10" style={{ stroke: "var(--track)" }} />
              <circle
                cx="42" cy="42" r="32" fill="none" strokeWidth="10" strokeLinecap="round"
                strokeDasharray="201" strokeDashoffset="60"
                style={{ stroke: "var(--accent)" }}
              />
            </svg>
            <div className="skeleton-bar h-3 w-16 rounded" />
          </div>
        </div>

        <div className="font-mono text-[11px] mt-5 leading-relaxed" style={{ color: "var(--ink-soft)" }}>
          {failed ? (
            <>The API hasn&apos;t answered after {elapsed}s. It may still be deploying — retry, or continue and the console will reconnect live.</>
          ) : (
            <>First load wakes the server and loads the rule packs + learned model. The live console appears automatically — no refresh needed.</>
          )}
        </div>
        <div className="flex items-center gap-2 mt-4">
          <button onClick={onRetry} className="btn-primary">
            <span className="material-symbols-outlined text-[17px]">refresh</span>
            <span>{failed ? "Retry now" : "Check now"}</span>
          </button>
          <button onClick={onContinue} className="btn-ghost">Continue anyway</button>
        </div>
      </div>
    </div>
  );
}
