import { Link, useLocation } from "react-router-dom";
import { useApi, API } from "../lib/api";
import { scoreColor } from "../lib/ui";
import Logo from "./Logo";
import { ThemeToggle } from "./ThemeToggle";

export default function Header() {
  const { data } = useApi("/dashboard");
  const { data: queue } = useApi("/training/stats");
  const { data: health } = useApi("/health");
  const location = useLocation();

  const fleet = data?.fleet_compliance_score;
  const pending = queue?.total_mappings - queue?.total_matches >= 0 ? null : null; // placeholder, replaced below
  const fleetScore = fleet !== null && fleet !== undefined ? `${fleet}% Score` : "—";
  const deviceCount = data?.device_count ?? 0;
  const compliant = (data?.devices || []).filter((d) => (d.compliance_pct ?? 0) >= 80).length;

  const nav = [
    { to: "/console", label: "Dashboard", icon: "grid_view", end: true },
    { to: "/console/devices", label: "Devices", icon: "router" },
    { to: "/console/training", label: "Training Loop", icon: "psychology" },
    { to: "/console/upload", label: "Ingest", icon: "add_circle" },
    { to: "/console/reports", label: "Reports", icon: "verified" },
  ];

  return (
    <header className="fixed top-0 w-full z-50 bg-tacticalOlive border-b border-camoSeam text-softSage shadow-md">
      <div className="h-16 w-full px-6 flex items-center justify-between gap-4">
        {/* Left: brand — click to return to landing page */}
        <Link to="/" className="flex items-center gap-3 min-w-[300px] group" title="Back to landing page">
          <Logo className="h-9 w-9 rounded-lg" />
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-display font-semibold text-base text-softSage tracking-tight group-hover:opacity-80 transition-opacity">ComplianceForge</span>
            </div>
            <span className="font-sans text-xs text-sageMuted">
              Unified Network Control Plane v1.0 (Advisory-Only Remediation)
            </span>
          </div>
        </Link>

        {/* Framework pills + AI mode */}
        <div className="hidden xl:flex items-center gap-1.5 bg-olivePanel px-2.5 py-1 rounded-md border border-camoSeam">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-sprucePine border border-mutedMeadow/50 text-[#FCF9F0] font-mono text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-mutedMeadow animate-pulse"></span>
            <span>CIS · NIST · STIG · ISO views</span>
          </div>
          <div
            className="flex items-center gap-1.5 px-2 py-0.5 rounded text-sageMuted font-mono text-[11px]"
            title={
              health
                ? `Dataset: ${health.dataset_size ?? "?"} examples · Model v${health.model_version ?? 0}${
                    health.model_accuracy != null ? ` · acc ${Math.round(health.model_accuracy * 100)}%` : ""
                  } · ${health.ai_label || ""}`
                : "AI classifier mode"
            }
          >
            <span
              className="w-1.5 h-1.5 rounded-full animate-pulse"
              style={{ background: health?.ai_mode === "deterministic" ? "var(--warn)" : "var(--pass)" }}
            ></span>
            <span>
              {health?.ai_mode === "local_lm"
                ? "AI: Local LM"
                : health?.ai_mode === "llm"
                  ? "AI: Cloud LLM"
                  : health?.ai_mode === "deterministic"
                    ? "Deterministic · LLM-ready"
                    : "AI: …"}
            </span>
            {health?.model_version > 0 && (
              <span className="ml-1 px-1.5 py-px rounded bg-sprucePine border border-mutedMeadow/50 text-[#FCF9F0]">
                v{health.model_version}
                {health.model_accuracy != null ? ` · ${Math.round(health.model_accuracy * 100)}%` : ""} ·{" "}
                {health.dataset_size ?? 0} ex
              </span>
            )}
          </div>
        </div>

        {/* Right actions */}
        <div className="flex items-center gap-3">
          <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded bg-olivePanel border border-camoSeam">
            <span className="w-2 h-2 rounded-full bg-mutedMeadow"></span>
            <span className="font-mono text-xs text-sageMuted">
              Engine Online | Fleet: <strong className="text-softSage font-mono">{fleetScore}</strong>
            </span>
          </div>
          <Link to="/console/upload" className="flex items-center gap-1.5 bg-sprucePine hover:bg-sprucePineHover text-[#FCF9F0] text-xs font-semibold px-3 py-2 rounded border border-[#8A3A1D] transition-all shadow-sm">
            <span className="material-symbols-outlined text-[18px]">add_circle</span>
            <span>Ingest Raw Config</span>
          </Link>
          <ThemeToggle />
          <div className="h-6 w-px bg-camoSeam hidden sm:block"></div>
          <div className="flex items-center gap-2.5">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-softSage leading-tight font-display">Auditor SEC-9</div>
              <div className="font-mono text-[10px] text-sageMuted">Admin / Human-in-the-Loop</div>
            </div>
            <div className="w-8 h-8 rounded bg-camoSeam border border-[#5C4A35] flex items-center justify-center text-softSage">
              <span className="material-symbols-outlined text-[18px]">person</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
