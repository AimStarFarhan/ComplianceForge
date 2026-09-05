import { Link, useLocation } from "react-router-dom";
import { useApi, API } from "../lib/api";
import { scoreColor } from "../lib/ui";

export default function Header() {
  const { data } = useApi("/dashboard");
  const { data: queue } = useApi("/training/stats");
  const location = useLocation();

  const fleet = data?.fleet_compliance_score;
  const pending = queue?.total_mappings - queue?.total_matches >= 0 ? null : null; // placeholder, replaced below
  const fleetScore = fleet !== null && fleet !== undefined ? `${fleet}% Score` : "—";
  const deviceCount = data?.device_count ?? 0;
  const compliant = (data?.devices || []).filter((d) => (d.compliance_pct ?? 0) >= 80).length;

  const nav = [
    { to: "/", label: "Dashboard", icon: "grid_view", end: true },
    { to: "/devices", label: "Devices", icon: "router" },
    { to: "/training", label: "Training Loop", icon: "psychology" },
    { to: "/upload", label: "Ingest", icon: "add_circle" },
    { to: "/reports", label: "Reports", icon: "verified" },
  ];

  return (
    <header className="fixed top-0 w-full z-50 bg-tacticalOlive border-b border-camoSeam text-softSage shadow-md">
      <div className="h-16 w-full px-6 flex items-center justify-between gap-4">
        {/* Left: brand */}
        <div className="flex items-center gap-3 min-w-[300px]">
          <div className="h-8 w-8 rounded bg-olivePanel border border-camoSeam flex items-center justify-center font-mono font-bold text-sm text-softSage">
            CF
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-base text-white tracking-tight">ComplianceForge</span>
              <span className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded bg-camoSeam text-softSage border border-softSage/30">
                SIH26155 / NTRO
              </span>
            </div>
            <span className="font-sans text-xs text-sageMuted">
              Unified Network Control Plane v1.0 (Advisory-Only Remediation)
            </span>
          </div>
        </div>

        {/* Framework pills */}
        <div className="hidden xl:flex items-center gap-1.5 bg-olivePanel px-2.5 py-1 rounded-md border border-camoSeam">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-sprucePine border border-mutedMeadow/50 text-white font-mono text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-mutedMeadow animate-pulse"></span>
            <span>CIS-Style Pack v1</span>
          </div>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded text-sageMuted font-mono text-[11px]">
            <span>NIST SP 800-53</span>
          </div>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded text-sageMuted font-mono text-[11px]">
            <span>DISA STIG</span>
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
          <Link to="/upload" className="flex items-center gap-1.5 bg-sprucePine hover:bg-sprucePineHover text-white text-xs font-semibold px-3 py-2 rounded border border-[#3E5C47] transition-all shadow-sm">
            <span className="material-symbols-outlined text-[18px]">add_circle</span>
            <span>Ingest Raw Config</span>
          </Link>
          <div className="h-6 w-px bg-camoSeam hidden sm:block"></div>
          <div className="flex items-center gap-2.5">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-white leading-tight font-display">Auditor SEC-9</div>
              <div className="font-mono text-[10px] text-sageMuted">Admin / Human-in-the-Loop</div>
            </div>
            <div className="w-8 h-8 rounded bg-camoSeam border border-[#526350] flex items-center justify-center text-softSage">
              <span className="material-symbols-outlined text-[18px]">person</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
