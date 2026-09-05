import { useState } from "react";
import { API, useApi } from "../lib/api";
import { useToast } from "../components/Toast";

export default function ReportPreview() {
  const { data, loading, error } = useApi("/dashboard");
  const [msg, setMsg] = useState("");
  const toast = useToast();

  const devices = (data?.devices || []).filter((d) => d.audited);

  const download = (d) => {
    toast("Compiling PDF audit report…");
    const token = window.localStorage.getItem("cf-token");
    fetch(`${API}/report/${encodeURIComponent(d.device_id)}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `complianceforge_${d.device_id}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        setMsg(`Downloaded complianceforge_${d.device_id}.pdf`);
      })
      .catch((e) => setMsg(`Report failed: ${e.message} — audit the device first.`));
  };

  return (
    <>
      <div className="flex items-center gap-2.5">
        <span className="material-symbols-outlined text-sprucePine text-[24px]">verified</span>
        <div>
          <span className="font-display text-base font-bold text-peatCharcoal">Reports &amp; Evidence</span>
          <span className="font-sans text-xs text-taupe-muted block">Per-device PDF audits: identification, executive summary, findings with source, remediation appendix</span>
        </div>
      </div>

      {loading && <div className="font-mono text-xs text-taupe-muted">Loading audited devices…</div>}
      {error && <div className="font-mono text-xs text-terracottaRust">Backend unreachable: {error}</div>}
      {msg && (
        <div className="card p-3 font-mono text-xs text-peatCharcoal">
          <span className="material-symbols-outlined text-[15px] text-mutedMeadow align-middle mr-1.5">info</span>
          {msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {devices.map((d) => {
          const pct = d.compliance_pct;
          const color = pct >= 80 ? "#2D6A4F" : pct >= 50 ? "#C27803" : "#B84A39";
          return (
            <div key={d.device_id} className="card p-4 flex items-center justify-between gap-4">
              <div>
                <div className="font-display text-sm font-bold text-peatCharcoal">
                  {d.hostname || d.device_id}
                  <span className="font-mono text-[10px] text-taupe-muted ml-2 uppercase">{d.vendor_label}</span>
                </div>
                <div className="font-mono text-[11px] text-taupe-muted mt-1">
                  {d.pass_count} pass · {d.fail_count} fail · audit #{d.run_id}
                </div>
                <div className="mt-2 h-1.5 w-40 bg-creamParchment rounded-full overflow-hidden border border-weatheredTaupe/60">
                  <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }}></div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="font-display text-3xl font-bold" style={{ color }}>{Math.round(pct)}%</div>
                <button onClick={() => download(d)} className="btn-primary !py-1.5">
                  <span className="material-symbols-outlined text-[16px]">picture_as_pdf</span>
                  <span>Export PDF</span>
                </button>
              </div>
            </div>
          );
        })}
        {devices.length === 0 && (
          <div className="card p-6 font-mono text-xs text-taupe-muted text-center lg:col-span-2">
            No audited devices yet — ingest and audit a device to generate its first report.
          </div>
        )}
      </div>

      <div className="card p-4 font-mono text-[11px] leading-relaxed text-taupe-muted">
        <strong className="text-peatCharcoal">Every report carries the disclaimer:</strong> "Remediation commands are
        advisory. Apply in a maintenance window after review — not for unattended auto-execution." Auto-push of config
        changes to live devices is a stated v1 security boundary, not a gap.
      </div>
    </>
  );
}
