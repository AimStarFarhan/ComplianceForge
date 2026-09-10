import { Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { timeAgo } from "../lib/ui";

export default function Devices() {
  const { data, loading, error } = useApi("/devices");

  if (loading) return <div className="font-mono text-xs text-taupe-muted">Loading device inventory…</div>;
  if (error) return <div className="font-mono text-xs text-terracottaRust">Backend unreachable: {error}</div>;

  const devices = data?.devices || [];

  return (
    <>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className="material-symbols-outlined text-sprucePine text-[24px]">terminal</span>
          <div>
            <span className="font-display text-base font-bold text-peatCharcoal">Audits &amp; Remediation</span>
            <span className="font-sans text-xs text-taupe-muted block">{devices.length} devices in fleet inventory</span>
          </div>
        </div>
        <Link to="/console/upload" className="btn-primary">
          <span className="material-symbols-outlined text-[16px]">add_circle</span>
          <span>Ingest Raw Config</span>
        </Link>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="tbl">
            <thead>
              <tr>
                <th>Hostname / ID</th>
                <th>Vendor</th>
                <th>OS</th>
                <th>Compliance</th>
                <th>Pass / Fail</th>
                <th>Queue</th>
                <th>Last Audit</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => {
                const pct = d.compliance_pct;
                const color = pct === null || pct === undefined ? "var(--ink-soft)" : pct >= 80 ? "var(--pass)" : pct >= 50 ? "var(--warn)" : "var(--fail)";
                return (
                  <tr key={d.device_id}>
                    <td>
                      <Link to={`/console/devices/${encodeURIComponent(d.device_id)}`} className="font-display text-sm font-bold text-peatCharcoal hover:text-sprucePine">
                        {d.hostname || d.device_id}
                      </Link>
                      <div className="font-mono text-[10px] text-taupe-muted">{d.device_id}</div>
                    </td>
                    <td>
                      <span className="font-mono text-[11px] text-taupe-muted">
                        {d.vendor_label}
                        {d.is_unseen_vendor && <span className="ml-1.5 px-1.5 py-0.5 rounded bg-ochreWash text-ochreHazard border border-ochreHazard/40 text-[9px] font-bold">UNSEEN</span>}
                      </span>
                    </td>
                    <td className="font-mono text-[11px] text-taupe-muted">{d.os_version || "—"}</td>
                    <td>
                      <span className="font-display font-bold" style={{ color }}>{pct ?? "—"}{pct != null && "%"}</span>
                    </td>
                    <td className="font-mono text-[11px]">
                      <span className="text-mutedMeadow font-bold">{d.pass_count}</span>
                      <span className="text-taupe-muted"> / </span>
                      <span className="text-terracottaRust font-bold">{d.fail_count}</span>
                    </td>
                    <td className="font-mono text-[11px]">{d.unparsed_count || 0}</td>
                    <td className="font-mono text-[10px] text-taupe-muted">{timeAgo(d.last_audit)}</td>
                    <td>
                      <Link to={`/console/devices/${encodeURIComponent(d.device_id)}`} className="btn-ghost !py-1 !px-2 !text-[10px]">OPEN →</Link>
                    </td>
                  </tr>
                );
              })}
              {devices.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center font-mono text-xs text-taupe-muted py-8">
                    No devices onboarded — ingest a config to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
