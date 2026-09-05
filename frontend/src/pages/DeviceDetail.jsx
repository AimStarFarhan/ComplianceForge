import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, useApi } from "../lib/api";
import { timeAgo } from "../lib/ui";
import { useToast, copyText } from "../components/Toast";

const order = { critical: 0, high: 1, medium: 2, low: 3 };

function RemediationCard({ f, toast }) {
  const sevColor = f.severity === "high" || f.severity === "critical" ? "#B84A39" : "#C27803";
  return (
    <div className="card overflow-hidden">
      <div className="p-4 border-l-4 flex flex-col gap-3" style={{ borderColor: sevColor }}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-col">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="badge text-white uppercase" style={{ background: sevColor }}>
                {f.severity} SEVERITY
              </span>
              <span className="font-display text-sm font-bold text-peatCharcoal">{f.rule_id} — {f.title}</span>
            </div>
            <span className="font-mono text-xs text-taupe-muted mt-1">
              Maps to: {f.maps_to || "—"}
              {f.source === "ai_suggested_human_confirmed" && (
                <span className="ml-2 px-1.5 py-0.5 rounded bg-sprucePine text-white font-bold text-[10px]">AI + HUMAN-CONFIRMED SOURCE</span>
              )}
            </span>
          </div>
          <span className="badge uppercase" style={{ background: f.status === "pass" ? "#E8F2EC" : "#FBECEB", color: f.status === "pass" ? "#2D6A4F" : "#B84A39", border: `1px solid ${f.status === "pass" ? "#2D6A4F40" : "#B84A3940"}` }}>
            {f.status}
          </span>
        </div>

        {f.evidence && (
          <div className="pane p-3 font-mono text-xs text-peatCharcoal">
            <div className="font-bold mb-1 flex items-center gap-1.5" style={{ color: sevColor }}>
              <span className="material-symbols-outlined text-[16px]">dangerous</span>
              <span>Finding evidence (normalized baseline):</span>
            </div>
            <p className="font-sans text-xs leading-relaxed">{f.evidence}</p>
            {f.explanation && <p className="font-sans text-xs leading-relaxed mt-2 text-taupe-muted">{f.explanation}</p>}
          </div>
        )}

        {f.status === "fail" && f.remediation && (
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="label-xs flex items-center gap-1">
                <span className="material-symbols-outlined text-mutedMeadow text-[15px]">terminal</span>
                Target Safe Remediation (vendor syntax)
              </span>
              <button className="btn-copy" onClick={() => copyText(f.remediation, toast, "Remediation CLI copied to clipboard")}>
                <span className="material-symbols-outlined text-[14px]">file_copy</span>
                <span className="font-semibold">Copy CLI</span>
              </button>
            </div>
            <pre className="code-pane text-sprucePine font-semibold">{f.remediation}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

export default function DeviceDetail() {
  const { deviceId } = useParams();
  const { data, error, loading, reload } = useApi(`/devices/${encodeURIComponent(deviceId)}`, [deviceId]);
  const [auditing, setAuditing] = useState(false);
  const [training, setTraining] = useState(false);
  const [tab, setTab] = useState("json");
  const toast = useToast();

  const trainDevice = async () => {
    setTraining(true);
    try {
      const res = await api("/training/train-device", {
        method: "POST",
        body: { device_id: deviceId, confirmed_by: "admin" },
      });
      toast(`Vendor trained — ${res.trained_lines} mappings confirmed (${res.already_learned} already known). Run the audit now.`);
      reload();
    } catch (e) {
      toast(`Training failed: ${e.message}`);
    } finally {
      setTraining(false);
    }
  };

  const runAudit = async () => {
    setAuditing(true);
    try {
      const res = await api(`/audit/${encodeURIComponent(deviceId)}`, { method: "POST" });
      toast(`Audit complete — ${res.summary.pass_count} pass / ${res.summary.fail_count} fail / ${res.unparsed_count} to training queue`);
      reload();
    } catch (e) {
      toast(`Audit failed: ${e.message}`);
    } finally {
      setAuditing(false);
    }
  };

  const exportPdf = async () => {
    toast("Compiling NTRO cryptographic PDF audit report…");
    try {
      const token = window.localStorage.getItem("cf-token");
      const r = await fetch(`${import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000"}/report/${encodeURIComponent(deviceId)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `complianceforge_${deviceId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast("PDF report downloaded");
    } catch (e) {
      toast(`Report failed: ${e.message} — audit the device first`);
    }
  };

  const copyRunbook = async () => {
    const fails = (data?.findings || []).filter((f) => f.status === "fail" && f.remediation);
    if (!fails.length) return toast("No failed rules — nothing to remediate");
    const runbook = [
      "! ==============================================",
      "! ComplianceForge Consolidated Safe Remediation Runbook",
      `! Target: ${data?.hostname || deviceId}`,
      "! Advisory only — apply in a maintenance window",
      "! ==============================================",
      "",
      ...fails.flatMap((f) => [`! [${f.rule_id}] ${f.title}`, f.remediation, ""]),
      "! End of runbook",
    ].join("\n");
    await copyText(runbook, toast, `Runbook (${fails.length} clauses) copied to clipboard`);
  };

  if (loading) return <div className="font-mono text-xs text-taupe-muted">Loading device audit…</div>;
  if (error) return <div className="font-mono text-xs text-terracottaRust">{error}</div>;

  const s = data?.summary;
  const findings = (data?.findings || []).slice().sort((a, b) => order[a.severity] - order[b.severity]);
  const fails = findings.filter((f) => f.status === "fail");
  const crit = (s?.failed_by_severity?.critical ?? 0) + (s?.failed_by_severity?.high ?? 0);
  const hist = (data?.history || []).slice(-4);

  return (
    <>
      {/* Device banner */}
      <div className="card p-5">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className="w-13 h-13 p-3 rounded-md bg-creamParchment border border-weatheredTaupe flex items-center justify-center text-sprucePine shadow-inner">
              <span className="material-symbols-outlined text-[30px]">router</span>
            </div>
            <div className="flex flex-col">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-display text-xl text-peatCharcoal font-bold tracking-tight">{data.hostname || deviceId}</span>
                <span className="pill-device">{data.vendor_label}</span>
                {data.os_version && <span className="pill-meta">{data.os_version}</span>}
                <span
                  className="px-2.5 py-0.5 rounded font-mono text-[11px] font-bold uppercase flex items-center gap-1.5"
                  style={{
                    background: fails.length ? "#FBECEB" : "#E8F2EC",
                    color: fails.length ? "#B84A39" : "#2D6A4F",
                    border: `1px solid ${fails.length ? "#B84A3966" : "#2D6A4F66"}`,
                  }}
                >
                  <span className="w-1.5 h-1.5 rounded-full animate-ping" style={{ background: "currentColor" }}></span>
                  {s ? (fails.length ? `AUDIT FAILED (${fails.length} ISSUES)` : "VERIFIED CLEAN") : "NOT AUDITED"}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-taupe-muted font-mono text-xs">
                <span>ID: <strong className="text-peatCharcoal font-mono">{deviceId}</strong></span>
                {data.model && (<><span className="text-weatheredTaupe">|</span><span>Model: <strong className="text-peatCharcoal">{data.model}</strong></span></>)}
                <span className="text-weatheredTaupe">|</span>
                <span>Parser: <strong className="text-sprucePine">vendor-neutral baseline v1</strong></span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-3.5 bg-creamParchment border border-weatheredTaupe px-4 py-2.5 rounded-md shadow-sm">
              <div className="w-13 h-13 flex items-center justify-center">
                <svg className="w-13 h-13 -rotate-90" viewBox="0 0 48 48">
                  <circle className="text-weatheredTaupe" cx="24" cy="24" fill="none" r="20" stroke="currentColor" strokeWidth="4.5" />
                  <circle
                    cx="24" cy="24" fill="none" r="20" stroke={s ? ((s.compliance_pct ?? 0) >= 80 ? "#2D6A4F" : (s.compliance_pct ?? 0) >= 50 ? "#C27803" : "#B84A39") : "#D6D0C4"}
                    strokeDasharray="125.6" strokeDashoffset={s ? 125.6 * (1 - s.compliance_pct / 100) : 125.6}
                    strokeLinecap="round" strokeWidth="4.5"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center">
                  <span className="font-display text-base font-bold text-peatCharcoal leading-none">{s ? Math.round(s.compliance_pct) : "—"}</span>
                  <span className="font-mono text-[8px] text-taupe-muted uppercase leading-none mt-0.5">%</span>
                </div>
              </div>
              <div className="flex flex-col">
                <span className="font-mono text-[10px] uppercase tracking-wider text-taupe-muted">CIS-Style Compliance Index</span>
                <span className="font-sans text-xs font-bold" style={{ color: s ? ((s.compliance_pct ?? 0) >= 80 ? "#2D6A4F" : "#C27803") : "#726F67" }}>
                  {s ? `${s.pass_count} of ${s.total_rules} checks pass` : "Run first audit"}
                </span>
                <span className="font-mono text-[10px] text-taupe-muted">{data.vendor_label} rule pack</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={exportPdf} className="btn-ghost">
                <span className="material-symbols-outlined text-[17px] text-sprucePine">picture_as_pdf</span>
                <span>Generate PDF</span>
              </button>
              <button onClick={copyRunbook} className="btn-ghost">
                <span className="material-symbols-outlined text-[17px] text-mutedMeadow">content_copy</span>
                <span>Copy Runbook</span>
              </button>
              {data.vendor === "unseen_vendor" && !s && (
                <button onClick={trainDevice} disabled={training} className="btn-primary !bg-ochreHazard !border-[#8F5802]">
                  <span className="material-symbols-outlined text-[17px]">model_training</span>
                  <span>{training ? "Training…" : "Train Vendor"}</span>
                </button>
              )}
              <button onClick={runAudit} disabled={auditing} className="btn-primary">
                <span className="material-symbols-outlined text-[17px]">{auditing ? "hourglass_top" : "play_arrow"}</span>
                <span>{auditing ? "Auditing…" : "Run Audit"}</span>
              </button>
            </div>
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-weatheredTaupe flex flex-col md:flex-row items-start md:items-center justify-between gap-2 bg-creamParchment/60 px-3 py-2 rounded">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-sprucePine text-[18px]">verified_user</span>
            <span className="font-mono text-xs text-peatCharcoal">
              <strong>Advisory-Only Safe Guard:</strong> runbook formatted for staging verification — <span className="text-terracottaRust font-bold">zero blind auto-push execution</span>.
            </span>
          </div>
          <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-warm-sandstone border border-weatheredTaupe text-taupe-muted font-semibold">POLICY ENFORCED // SEC-AUDIT-L1</span>
        </div>
      </div>

      {/* Bento */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-warm-sandstone border border-weathered-taupe p-4 rounded-lg shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-taupe-muted">
            <span className="label-xs">Severity: Critical</span>
            <span className="material-symbols-outlined text-terracottaRust text-[20px]">error</span>
          </div>
          <div className="my-2">
            <div className="font-display text-3xl font-bold text-terracottaRust leading-none">{String(s?.failed_by_severity?.critical ?? 0).padStart(2, "0")}</div>
            <div className="font-sans text-xs text-peatCharcoal font-medium mt-1">Critical violations detected</div>
          </div>
          <div className="h-1.5 w-full bg-creamParchment rounded-full overflow-hidden border border-weathered-taupe/60">
            <div className="h-full bg-terracottaRust rounded-full" style={{ width: `${Math.min(100, (s?.failed_by_severity?.critical ?? 0) * 25)}%` }}></div>
          </div>
        </div>
        <div className="bg-warm-sandstone border border-weathered-taupe p-4 rounded-lg shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-taupe-muted">
            <span className="label-xs">Severity: Medium</span>
            <span className="material-symbols-outlined text-ochreHazard text-[20px]">warning</span>
          </div>
          <div className="my-2">
            <div className="font-display text-3xl font-bold text-ochreHazard leading-none">{String(s?.failed_by_severity?.medium ?? 0).padStart(2, "0")}</div>
            <div className="font-sans text-xs text-peatCharcoal font-medium mt-1">Medium-severity gaps</div>
          </div>
          <div className="h-1.5 w-full bg-creamParchment rounded-full overflow-hidden border border-weathered-taupe/60">
            <div className="h-full bg-ochreHazard rounded-full" style={{ width: `${Math.min(100, (s?.failed_by_severity?.medium ?? 0) * 15)}%` }}></div>
          </div>
        </div>
        <div className="bg-warm-sandstone border border-weathered-taupe p-4 rounded-lg shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-taupe-muted">
            <span className="label-xs">Active Standard</span>
            <span className="material-symbols-outlined text-sprucePine text-[20px]">fact_check</span>
          </div>
          <div className="my-2">
            <div className="font-display text-lg font-bold text-peatCharcoal">CIS-Style Pack</div>
            <div className="font-mono text-xs text-taupe-muted mt-0.5">Profile: {data.vendor_label}</div>
          </div>
          <div className="flex items-center justify-between font-mono text-[11px] font-semibold text-mutedMeadow">
            <span>{s ? `${s.pass_count} of ${s.total_rules} checks valid` : "—"}</span>
            <span className="bg-mutedMeadow/15 px-1.5 py-0.5 rounded">{s ? `${s.compliance_pct}% PASS` : "—"}</span>
          </div>
        </div>
        <div className="bg-warm-sandstone border border-weathered-taupe p-4 rounded-lg shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-taupe-muted">
            <span className="label-xs">Training Queue</span>
            <span className="material-symbols-outlined text-mutedMeadow text-[20px]">lock_clock</span>
          </div>
          <div className="my-2">
            <div className="font-display text-lg font-bold text-mutedMeadow">{s ? "Human Review" : "—"}</div>
            <div className="font-mono text-xs text-taupe-muted mt-0.5">{(data?.history || []).at(-1)?.unparsed_count ?? 0} unrecognized lines</div>
          </div>
          <div className="font-mono text-[10px] text-taupe-muted truncate">
            Routed to <Link to="/training" className="text-sprucePine font-bold">adaptive AI queue</Link>
          </div>
        </div>
      </div>

      {/* Dual pane */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* LEFT: tabs */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          <div className="card overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 bg-creamParchment border-b border-weatheredTaupe">
              <div className="flex items-center gap-1">
                {[
                  ["json", "Normalized Baseline"],
                  ["raw", "Raw Config"],
                ].map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => setTab(key)}
                    className={
                      tab === key
                        ? "px-2.5 py-1.5 rounded text-xs font-semibold bg-warm-sandstone text-peatCharcoal border border-weatheredTaupe shadow-sm"
                        : "px-2.5 py-1.5 rounded text-xs font-medium text-taupe-muted hover:text-peatCharcoal hover:bg-warm-sandstone/70"
                    }
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1.5 text-taupe-muted font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-mutedMeadow"></span>
                <span>Parser: {tab === "raw" ? "raw payload" : "OK"}</span>
              </div>
            </div>

            {tab === "json" ? (
              <div className="p-4 bg-creamParchment overflow-x-auto min-h-[420px] font-mono text-xs leading-relaxed text-peatCharcoal">
                <div className="flex items-center justify-between pb-2 mb-3 border-b border-weatheredTaupe text-taupe-muted text-[11px] uppercase">
                  <span>// Schema: complianceforge.baseline.security.v1</span>
                  <span>{data.vendor} baseline</span>
                </div>
                <pre className="leading-relaxed">{data.normalized ? JSON.stringify(data.normalized, null, 2).slice(0, 8000) : "// No baseline — ingest a config first"}</pre>
              </div>
            ) : (
              <div className="p-4 bg-creamParchment overflow-x-auto min-h-[420px] font-mono text-xs leading-relaxed text-peatCharcoal">
                <div className="flex items-center justify-between pb-2 mb-3 border-b border-weatheredTaupe text-taupe-muted text-[11px] uppercase">
                  <span>// Raw {data.vendor_label} CLI payload</span>
                  <span>Lines: {data.raw_config ? data.raw_config.split("\n").length : 0}</span>
                </div>
                <pre className="leading-relaxed">{data.raw_config || "// No raw config stored"}</pre>
              </div>
            )}

            <div className="px-4 py-2 bg-warm-sandstone border-t border-weatheredTaupe flex items-center justify-between text-taupe-muted font-mono text-[11px]">
              <span>Parser Engine: ComplianceForge Regex Normalizer</span>
              <span className="text-mutedMeadow font-semibold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-mutedMeadow"></span>Vendor-neutral baseline v1
              </span>
            </div>
          </div>

          {/* Ingest evidence badge */}
          <div className="p-3.5 rounded-lg bg-warm-sandstone border border-weatheredTaupe flex items-center justify-between shadow-sm">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded bg-creamParchment text-sprucePine border border-weatheredTaupe">
                <span className="material-symbols-outlined text-[20px]">hub</span>
              </div>
              <div>
                <div className="font-display text-xs text-peatCharcoal font-bold">Static File Ingest (v1 boundary)</div>
                <div className="font-mono text-[11px] text-taupe-muted">No live SSH polling — by design</div>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded bg-sprucePine text-white font-mono text-[10px] font-semibold tracking-wider">HUMAN-UPLOADED</span>
          </div>
        </div>

        {/* RIGHT: remediations */}
        <div className="lg:col-span-7 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-terracottaRust text-[22px]">security_update_warning</span>
              <span className="font-display text-base font-bold text-peatCharcoal">Explainable Remediations</span>
              <span className="px-2 py-0.5 rounded bg-rustWash text-terracottaRust border border-terracottaRust/30 font-mono text-[10px] font-bold">
                {fails.length} PENDING
              </span>
            </div>
            {fails.length > 0 && (
              <button onClick={copyRunbook} className="btn-primary">
                <span className="material-symbols-outlined text-[16px]">content_copy</span>
                <span>Copy Consolidated Runbook</span>
              </button>
            )}
          </div>

          {s ? (
            findings.map((f) => <RemediationCard key={f.rule_id} f={f} toast={toast} />)
          ) : (
            <div className="card p-6 font-mono text-xs text-taupe-muted text-center">
              No audit run yet — click RUN AUDIT to evaluate against the {data.vendor_label} rule pack.
            </div>
          )}
        </div>
      </div>

      {/* History timeline */}
      {hist.length > 0 && (
        <section className="card p-5">
          <div className="flex items-center gap-2.5 pb-3 border-b border-weatheredTaupe">
            <span className="material-symbols-outlined text-sprucePine text-[22px]">history_toggle_off</span>
            <div>
              <span className="font-display text-sm font-bold text-peatCharcoal">Audit History Timeline</span>
              <span className="font-sans text-xs text-taupe-muted block">Tracking compliance runs for '{data.hostname || deviceId}'</span>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            {hist.map((h, i) => {
              const isLast = i === hist.length - 1;
              const good = h.compliance_pct >= 80;
              return (
                <div
                  key={h.run_id}
                  className={`p-3.5 rounded-lg border relative ${isLast ? "bg-warm-sandstone border-2 border-sprucePine" : "bg-creamParchment border-weatheredTaupe"}`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span
                      className="font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border"
                      style={{
                        color: good ? "#2D6A4F" : "#C27803",
                        background: good ? "#2D6A4F10" : "#FDF5E6",
                        borderColor: good ? "#2D6A4F30" : "#C2780340",
                      }}
                    >
                      {h.compliance_pct}% COMPLIANCE
                    </span>
                    <span className="font-mono text-[11px] text-taupe-muted">{timeAgo(h.ran_at)}</span>
                  </div>
                  <div className="font-display text-xs font-bold text-peatCharcoal mt-1">Audit Run #{h.run_id}</div>
                  <p className="font-sans text-xs text-taupe-muted mt-1 leading-relaxed">
                    {h.pass_count} checks passed · {h.fail_count} failed · {h.unparsed_count} lines queued for training.
                  </p>
                  <div className="mt-3 pt-2 border-t border-weatheredTaupe font-mono text-[10px] text-taupe-muted">
                    {isLast ? "Latest state — authoritative" : "Historical snapshot"}
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </>
  );
}
