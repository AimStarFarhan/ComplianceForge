import { NavLink, Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { useJobs } from "../lib/jobs";
import { scoreColor } from "../lib/ui";

const JOB_PCT = { queued: 5, uploading: 30, normalized: 55, auditing: 80, scored: 100, train: 100, error: 100 };

const VENDORS = [
  { name: "Cisco IOS", key: "cisco_ios" },
  { name: "JunOS", key: "juniper_srx" },
  { name: "SONiC NOS", key: "sonic" },
  { name: "Unseen vendor", key: "unseen_vendor" },
];

export default function Sidebar() {
  const { data } = useApi("/dashboard");
  const { data: training } = useApi("/training/stats");

  const fleet = data?.fleet_compliance_score ?? 0;
  const deviceCount = data?.device_count ?? 0;
  const compliant = (data?.devices || []).filter((d) => (d.compliance_pct ?? 0) >= 80).length;

  const vendorStatus = {};
  (data?.by_vendor || []).forEach((v) => (vendorStatus[v.vendor] = v));
  const totalMappings = training?.total_mappings ?? 0;
  const { jobs, ACTIVE } = useJobs();
  const activeJobs = jobs.filter((j) => ACTIVE.includes(j.stage));

  const nav = [
    { to: "/console", label: "Dashboard & Fleet", icon: "grid_view", end: true },
    { to: "/console/training", label: "Training Loop", icon: "psychology" },
    { to: "/console/devices", label: "Audits & Remediation", icon: "terminal" },
    { to: "/console/reports", label: "Reports & Evidence", icon: "verified" },
  ];

  return (
    <aside className="fixed left-0 top-16 bottom-10 w-64 bg-tacticalOlive border-r border-camoSeam z-40 flex flex-col justify-between overflow-y-auto olive-scroll text-softSage">
      <div className="p-3.5 space-y-4">
        {/* Fleet Audit Scope Widget */}
        <div className="p-3 rounded-lg bg-olivePanel border border-camoSeam">
          <div className="flex items-center justify-between mb-1.5">
            <span className="font-mono text-[10px] uppercase text-sageMuted tracking-wider">Fleet Audit Scope</span>
            <span
              className="font-mono text-xs font-bold px-1.5 py-0.5 rounded"
              style={{ background: fleet >= 80 ? "var(--pass)" : fleet >= 50 ? "var(--warn)" : "var(--fail)", color: "var(--card)" }}
            >
              {fleet !== null && fleet !== undefined ? `${fleet}% Score` : "—"}
            </span>
          </div>
          <div className="flex items-center justify-between text-softSage mt-1">
            <span className="font-display text-base font-bold">{deviceCount} Devices</span>
            <span
              className={`font-mono text-[11px] px-1.5 py-0.5 rounded border ${
                compliant > 0
                  ? "bg-mutedMeadow/20 text-softSage border-mutedMeadow/40"
                  : "bg-oliveInk text-sageMuted border-camoSeam"
              }`}
            >
              {compliant} Compliant
            </span>
          </div>
          <div className="w-full bg-oliveInk h-1.5 rounded-full mt-2 overflow-hidden border border-camoSeam">
            <div
              className="h-full rounded-full"
              style={{ width: `${fleet || 0}%`, background: scoreColor(fleet) === "var(--pass)" ? "var(--pass)" : fleet >= 50 ? "var(--warn)" : "var(--fail)" }}
            ></div>
          </div>
        </div>

        {/* Compliance Operations Nav */}
        <div className="space-y-1">
          <div className="px-1 py-1 font-mono text-[10px] uppercase text-sageMuted tracking-wider">Compliance Operations</div>
          <nav className="space-y-1">
            {nav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  isActive
                    ? "flex items-center justify-between px-3 py-2 rounded-md bg-olivePanel text-softSage border-l-4 border-mutedMeadow font-semibold text-xs shadow-sm"
                    : "flex items-center justify-between px-3 py-2 rounded-md text-sageMuted hover:bg-oliveHover hover:text-softSage transition-all text-xs font-medium"
                }
              >
                <div className="flex items-center gap-2.5">
                  <span className="material-symbols-outlined text-[19px]">{item.icon}</span>
                  <span>{item.label}</span>
                </div>
              </NavLink>
            ))}
          </nav>
        </div>

        {/* Background processing — stays visible while switching tabs */}
        {jobs.length > 0 && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between px-1 py-0.5">
              <span className="font-mono text-[10px] uppercase text-sageMuted tracking-wider">
                Processing{activeJobs.length ? ` (${activeJobs.length})` : ""}
              </span>
              {activeJobs.length > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-mutedMeadow animate-pulse"></span>
              )}
            </div>
            <div className="space-y-1.5 px-0.5">
              {jobs.slice(0, 4).map((j) => (
                <Link
                  key={j.key}
                  to="/console/upload"
                  title={`${j.name} — ${j.stage}. Open lanes.`}
                  className="block p-1.5 rounded bg-olivePanel border border-camoSeam hover:bg-oliveHover transition-all"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[11px] text-softSage truncate">{j.name}</span>
                    <span className="font-mono text-[9px] uppercase text-sageMuted shrink-0">
                      {j.stage === "scored" && j.audit?.compliance_pct !== undefined
                        ? `${j.audit.compliance_pct}%`
                        : j.stage}
                    </span>
                  </div>
                  <div className="h-1 rounded-full mt-1 overflow-hidden bg-oliveInk border border-camoSeam">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${JOB_PCT[j.stage] ?? 0}%`,
                        background: j.stage === "error" ? "var(--fail)" : "var(--pass)",
                      }}
                    />
                  </div>
                </Link>
              ))}
              {jobs.length > 4 && (
                <Link to="/console/upload" className="block text-center font-mono text-[10px] text-sageMuted hover:text-softSage">
                  +{jobs.length - 4} more in lanes →
                </Link>
              )}
            </div>
          </div>
        )}

        {/* Vendor Parsers Widget */}
        <div className="space-y-1.5">
          <div className="px-1 py-0.5 font-mono text-[10px] uppercase text-sageMuted tracking-wider">Vendor Parsers</div>
          <div className="grid grid-cols-2 gap-1.5 px-0.5">
            {VENDORS.map((v) => {
              const known = vendorStatus[v.key];
              const online = v.key === "unseen_vendor" || known;
              return (
                <div key={v.key} className="p-1.5 rounded bg-olivePanel text-softSage font-mono text-[11px] flex items-center justify-between border border-camoSeam">
                  <span>{v.name}</span>
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ background: online ? "var(--pass)" : "#434F42" }}
                  ></span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Learned Mapping Cache */}
        <div className="space-y-1.5">
          <div className="px-1 py-0.5 font-mono text-[10px] uppercase text-sageMuted tracking-wider">Learned Rule Cache</div>
          <div className="px-1 space-y-1 font-mono text-[11px] text-softSage">
            <div className="flex items-center justify-between">
              <span className="text-sageMuted">Human-confirmed mappings</span>
              <span className="text-softSage font-bold">{totalMappings}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sageMuted">Auto-matches served</span>
              <span className="text-softSage font-bold">{training?.total_matches ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sageMuted">AI-confirmed share</span>
              <span className="text-softSage font-bold">
                {totalMappings ? `${Math.round(((training?.ai_confirmed ?? 0) / totalMappings) * 100)}%` : "—"}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-3 border-t border-camoSeam bg-oliveDeep">
        <div className="flex items-center justify-between text-sageMuted font-mono text-[11px]">
          <span className="flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[15px] text-softSage">lock</span>ComplianceForge
          </span>
          <span className="text-sageMuted/80">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
}
