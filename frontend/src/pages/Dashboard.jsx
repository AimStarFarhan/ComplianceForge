import { Link } from "react-router-dom";
import BentoCard, { ScoreGauge } from "../components/BentoCard";
import { useApi } from "../lib/api";

export default function Dashboard() {
  const { data, error, loading, reload } = useApi("/dashboard");

  if (loading) return <div className="font-mono text-xs text-taupe-muted">Loading fleet posture…</div>;
  if (error) return <div className="font-mono text-xs text-terracottaRust">Backend unreachable: {error}</div>;

  const fleet = data?.fleet_compliance_score;
  const devices = data?.devices || [];
  const sev = data?.severity_totals || {};
  const byVendor = data?.by_vendor || [];

  return (
    <>
      {/* Fleet banner */}
      <div className="card p-5">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className="w-13 h-13 p-3 rounded-md bg-creamParchment border border-weatheredTaupe flex items-center justify-center text-sprucePine shadow-inner">
              <span className="material-symbols-outlined text-[30px]">radar</span>
            </div>
            <div className="flex flex-col">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-display text-xl text-peatCharcoal font-bold tracking-tight">Fleet Compliance Posture</span>
                <span
                  className="px-2.5 py-0.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5"
                  style={{
                    background: (fleet ?? 0) >= 80 ? "#E8F2EC" : (fleet ?? 0) >= 50 ? "#FDF5E6" : "#FBECEB",
                    color: (fleet ?? 0) >= 80 ? "#2D6A4F" : (fleet ?? 0) >= 50 ? "#C27803" : "#B84A39",
                    border: `1px solid ${(fleet ?? 0) >= 80 ? "#2D6A4F55" : (fleet ?? 0) >= 50 ? "#C2780355" : "#B84A3955"}`,
                  }}
                >
                  <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "currentColor" }}></span>
                  {fleet === null || fleet === undefined ? "NO AUDITS YET" : `${devices.filter((d) => d.audited).length}/${data.device_count} DEVICES AUDITED`}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-taupe-muted font-mono text-xs">
                <span>Open findings: <strong className="text-peatCharcoal">{data.total_open_findings}</strong></span>
                <span className="text-weatheredTaupe">|</span>
                <span>Critical: <strong className="text-terracottaRust">{sev.critical ?? 0}</strong></span>
                <span className="text-weatheredTaupe">|</span>
                <span>High: <strong className="text-terracottaRust">{sev.high ?? 0}</strong></span>
                <span className="text-weatheredTaupe">|</span>
                <span>Medium: <strong className="text-ochreHazard">{sev.medium ?? 0}</strong></span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-3.5 bg-creamParchment border border-weatheredTaupe px-4 py-2.5 rounded-md shadow-sm">
              <ScoreGauge pct={fleet} />
              <div className="flex flex-col">
                <span className="font-mono text-[10px] uppercase tracking-wider text-taupe-muted">Fleet Compliance Index</span>
                <span className="font-sans text-xs font-bold" style={{ color: (fleet ?? 0) >= 80 ? "#2D6A4F" : (fleet ?? 0) >= 50 ? "#C27803" : "#B84A39" }}>
                  {fleet === null || fleet === undefined ? "Awaiting first audit" : `${fleet}% fleet average`}
                </span>
                <span className="font-mono text-[10px] text-taupe-muted">CIS-style packs: Cisco IOS / JunOS / SONiC</span>
              </div>
            </div>
            <button onClick={reload} className="btn-ghost">
              <span className="material-symbols-outlined text-[17px] text-sprucePine">refresh</span>
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Human-in-the-loop disclaimer */}
        <div className="mt-4 pt-3 border-t border-weatheredTaupe flex flex-col md:flex-row items-start md:items-center justify-between gap-2 bg-creamParchment/60 px-3 py-2 rounded">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-sprucePine text-[18px]">verified_user</span>
            <span className="font-mono text-xs text-peatCharcoal">
              <strong>Advisory-Only Safe Guard:</strong> remediation runbooks are staged for human review — <span className="text-terracottaRust font-bold">zero blind auto-push execution</span> against any control plane.
            </span>
          </div>
          <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-warm-sandstone border border-weatheredTaupe text-taupe-muted font-semibold">
            POLICY ENFORCED // SEC-AUDIT-L1
          </span>
        </div>
      </div>

      {/* Bento breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <BentoCard
          label="Severity: Critical"
          icon="error"
          digit={String(sev.critical ?? 0).padStart(2, "0")}
          title="Critical findings across fleet"
          accent="#B84A39"
          progress={Math.min(100, (sev.critical ?? 0) * 20)}
        />
        <BentoCard
          label="Severity: High"
          icon="warning"
          digit={String(sev.high ?? 0).padStart(2, "0")}
          title="High-severity hardening gaps"
          accent="#C27803"
          progress={Math.min(100, (sev.high ?? 0) * 15)}
        />
        <BentoCard
          label="Devices Onboarded"
          icon="router"
          digit={String(data.device_count).padStart(2, "0")}
          title={`${data.audited_count} audited · ${byVendor.length} vendor families`}
          accent="#1E3527"
        />
        <BentoCard
          label="Training Queue"
          icon="psychology"
          digit={String(devices.reduce((a, d) => a + (d.unparsed_count || 0), 0)).padStart(2, "0")}
          title="Unrecognized lines routed to human review"
          accent="#2D6A4F"
        />
      </div>

      {/* Device grid */}
      <section>
        <div className="label-md mb-2 flex items-center justify-between">
          <span>Fleet Devices — click to open audit</span>
          <Link to="/upload" className="btn-primary !py-1.5">
            <span className="material-symbols-outlined text-[16px]">add_circle</span>
            <span>Ingest New Device</span>
          </Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {devices.map((d) => {
            const band =
              d.compliance_pct === null || d.compliance_pct === undefined
                ? { label: "NOT AUDITED", cls: "status-na" }
                : d.compliance_pct >= 80
                ? { label: "COMPLIANT", cls: "status-pass" }
                : d.compliance_pct >= 50
                ? { label: "PARTIAL", cls: "status-error" }
                : { label: "NON-COMPLIANT", cls: "status-fail" };
            return (
              <Link key={d.device_id} to={`/devices/${encodeURIComponent(d.device_id)}`} className="card p-4 flex flex-col gap-3 hover:border-sprucePine transition-all">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-display text-sm font-bold text-peatCharcoal">{d.hostname || d.device_id}</div>
                    <div className="font-mono text-[11px] text-taupe-muted">{d.vendor_label}{d.os_version ? ` · ${d.os_version}` : ""}</div>
                  </div>
                  <span className={band.cls}>{band.label}</span>
                </div>
                <div className="flex items-end justify-between">
                  <div>
                    <div className="font-display text-2xl font-bold leading-none" style={{ color: d.compliance_pct >= 80 ? "#2D6A4F" : d.compliance_pct >= 50 ? "#C27803" : d.compliance_pct === null || d.compliance_pct === undefined ? "#726F67" : "#B84A39" }}>
                      {d.compliance_pct ?? "—"}{d.compliance_pct != null && "%"}
                    </div>
                    <div className="font-mono text-[11px] text-taupe-muted mt-1">
                      {d.pass_count} pass / {d.fail_count} fail · queue {d.unparsed_count}
                    </div>
                  </div>
                  {d.is_unseen_vendor && (
                    <span className="badge bg-ochreWash text-ochreHazard border border-ochreHazard/40">UNSEEN VENDOR</span>
                  )}
                </div>
              </Link>
            );
          })}
          {devices.length === 0 && (
            <div className="card p-6 font-mono text-xs text-taupe-muted md:col-span-2 xl:col-span-3 text-center">
              No devices onboarded — ingest your first config to begin.
            </div>
          )}
        </div>
      </section>

      {/* Vendor posture */}
      <section className="card p-5">
        <div className="flex items-center gap-2.5 pb-3 border-b border-weatheredTaupe">
          <span className="material-symbols-outlined text-sprucePine text-[22px]">fact_check</span>
          <div>
            <span className="font-display text-sm font-bold text-peatCharcoal">Posture by Vendor Family</span>
            <span className="font-sans text-xs text-taupe-muted block">Every parser normalizes into the same vendor-neutral security baseline</span>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
          {byVendor.map((v) => (
            <div key={v.vendor} className="p-3.5 rounded-lg bg-creamParchment border border-weatheredTaupe">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border"
                      style={{ color: "#2D6A4F", background: "#2D6A4F10", borderColor: "#2D6A4F30" }}>
                  {v.audited}/{v.devices} AUDITED
                </span>
                <span className="font-mono text-[11px] text-taupe-muted">{v.label}</span>
              </div>
              <div className="font-display text-2xl font-bold mt-1" style={{ color: v.avg_compliance >= 80 ? "#2D6A4F" : v.avg_compliance >= 50 ? "#C27803" : "#B84A39" }}>
                {v.avg_compliance === null || v.avg_compliance === undefined ? "—" : `${v.avg_compliance}%`}
              </div>
              <div className="font-mono text-[10px] text-taupe-muted mt-0.5">avg compliance index</div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
