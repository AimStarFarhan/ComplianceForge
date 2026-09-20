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
                    background: (fleet ?? 0) >= 80 ? "var(--pass-wash)" : (fleet ?? 0) >= 50 ? "var(--warn-wash)" : "var(--fail-wash)",
                    color: (fleet ?? 0) >= 80 ? "var(--pass)" : (fleet ?? 0) >= 50 ? "var(--warn)" : "var(--fail)",
                    border: `1px solid ${(fleet ?? 0) >= 80 ? "color-mix(in srgb, var(--pass) 33%, transparent)" : (fleet ?? 0) >= 50 ? "color-mix(in srgb, var(--warn) 33%, transparent)" : "color-mix(in srgb, var(--fail) 33%, transparent)"}`,
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
                <span className="font-sans text-xs font-bold" style={{ color: (fleet ?? 0) >= 80 ? "var(--pass)" : (fleet ?? 0) >= 50 ? "var(--warn)" : "var(--fail)" }}>
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
          accent="var(--fail)"
          progress={Math.min(100, (sev.critical ?? 0) * 20)}
        />
        <BentoCard
          label="Severity: High"
          icon="warning"
          digit={String(sev.high ?? 0).padStart(2, "0")}
          title="High-severity hardening gaps"
          accent="var(--warn)"
          progress={Math.min(100, (sev.high ?? 0) * 15)}
        />
        <BentoCard
          label="Devices Onboarded"
          icon="router"
          digit={String(data.device_count).padStart(2, "0")}
          title={`${data.audited_count} audited · ${byVendor.length} vendor families`}
          accent="var(--accent)"
        />
        <BentoCard
          label="Training Queue"
          icon="psychology"
          digit={String(devices.reduce((a, d) => a + (d.unparsed_count || 0), 0)).padStart(2, "0")}
          title="Unrecognized lines routed to human review"
          accent="var(--pass)"
        />
      </div>

      {/* Device grid */}
      <section>
        <div className="label-md mb-2 flex items-center justify-between">
          <span>Fleet Devices — click to open audit</span>
          <Link to="/console/upload" className="btn-primary !py-1.5">
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
              <Link key={d.device_id} to={`/console/devices/${encodeURIComponent(d.device_id)}`} className="card p-4 flex flex-col gap-3 hover:border-sprucePine transition-all">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-display text-sm font-bold text-peatCharcoal">{d.hostname || d.device_id}</div>
                    <div className="font-mono text-[11px] text-taupe-muted">{d.vendor_label}{d.os_version ? ` · ${d.os_version}` : ""}</div>
                  </div>
                  <span className={band.cls}>{band.label}</span>
                </div>
                <div className="flex items-end justify-between">
                  <div>
                    <div className="font-display text-2xl font-bold leading-none" style={{ color: d.compliance_pct >= 80 ? "var(--pass)" : d.compliance_pct >= 50 ? "var(--warn)" : d.compliance_pct === null || d.compliance_pct === undefined ? "var(--ink-soft)" : "var(--fail)" }}>
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
                      style={{ color: "var(--pass)", background: "color-mix(in srgb, var(--pass) 6%, transparent)", borderColor: "color-mix(in srgb, var(--pass) 19%, transparent)" }}>
                  {v.audited}/{v.devices} AUDITED
                </span>
                <span className="font-mono text-[11px] text-taupe-muted">{v.label}</span>
              </div>
              <div className="font-display text-2xl font-bold mt-1" style={{ color: v.avg_compliance >= 80 ? "var(--pass)" : v.avg_compliance >= 50 ? "var(--warn)" : "var(--fail)" }}>
                {v.avg_compliance === null || v.avg_compliance === undefined ? "—" : `${v.avg_compliance}%`}
              </div>
              <div className="font-mono text-[10px] text-taupe-muted mt-0.5">avg compliance index</div>
            </div>
          ))}
        </div>
      </section>
      {/* Audit history — every device that went through the audit tests */}
      <section className="card p-5">
        <div className="flex items-center gap-2.5 pb-3 border-b border-weatheredTaupe">
          <span className="material-symbols-outlined text-sprucePine text-[22px]">history</span>
          <div className="flex-1">
            <span className="font-display text-sm font-bold text-peatCharcoal">Audit History — devices through the audit tests</span>
            <span className="font-sans text-xs text-taupe-muted block">Newest run first · pass/fail per audit · provisional flags on CompilerAI-learned evidence</span>
          </div>
          {(data?.recent_audits?.length ?? 0) > 0 && (
            <span className="font-mono text-[10px] text-taupe-muted">{data.recent_audits.length} latest runs</span>
          )}
        </div>
        <div className="mt-3 overflow-x-auto">
          <table className="tbl">
            <thead>
              <tr>
                <th>Device</th>
                <th>Vendor</th>
                <th>Compliance</th>
                <th>Pass / Fail</th>
                <th>Queued</th>
                <th>Ran</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(data?.recent_audits || []).map((r) => (
                <tr key={r.run_id}>
                  <td className="font-mono text-[11px] font-bold text-peatCharcoal">
                    {r.hostname || r.device_id}
                    {r.is_unseen_vendor && <span className="ml-1.5 badge bg-ochreWash text-ochreHazard border border-ochreHazard/40">LEARNED</span>}
                  </td>
                  <td className="font-mono text-[11px] text-taupe-muted">{r.vendor_label || r.vendor}</td>
                  <td className="font-display text-sm font-bold" style={{ color: (r.compliance_pct ?? 0) >= 80 ? "var(--pass)" : (r.compliance_pct ?? 0) >= 50 ? "var(--warn)" : "var(--fail)" }}>
                    {r.compliance_pct ?? "—"}{r.compliance_pct != null && "%"}
                  </td>
                  <td className="font-mono text-[11px]"><span className="text-mutedMeadow font-bold">{r.pass_count} pass</span> / <span className="text-terracottaRust font-bold">{r.fail_count} fail</span></td>
                  <td className="font-mono text-[11px] text-taupe-muted">{r.unparsed_count}</td>
                  <td className="font-mono text-[10px] text-taupe-muted">{r.ran_at ? new Date(r.ran_at).toLocaleString() : "—"}</td>
                  <td>
                    <Link to={`/console/devices/${encodeURIComponent(r.device_id)}`} className="font-mono text-[10px] uppercase font-bold text-sprucePine hover:underline">
                      open →
                    </Link>
                  </td>
                </tr>
              ))}
              {(data?.recent_audits || []).length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center font-mono text-xs text-taupe-muted py-6">
                    No audits run yet — ingest a config and run the first audit to start the history.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
