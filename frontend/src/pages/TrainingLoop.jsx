import { useMemo, useState } from "react";
import { api, useApi } from "../lib/api";
import { useToast, copyText } from "../components/Toast";

const CATEGORIES = [
  "management_protocol", "ssh_policy", "authentication", "aaa", "password_policy",
  "logging", "syslog", "access_control", "acl_logging", "cryptography",
  "snmp_management", "ntp", "service_hardening", "banner", "privilege_escalation",
  "routing_integrity", "interface_security", "zone_policy", "unknown",
];

function ClusterCard({ cluster, onConfirmCluster, busy }) {
  const [selected, setSelected] = useState(cluster.ai_category || "unknown");
  const low = cluster.ai_confidence != null && cluster.ai_confidence < 0.7;

  return (
    <div className="card p-4 border-l-4 border-l-mutedMeadow">
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-xs px-2 py-1 rounded bg-creamParchment border border-weatheredTaupe text-peatCharcoal inline-block">
              {cluster.pattern}
            </code>
            <span className="px-2 py-0.5 rounded bg-sprucePine text-[#FCF9F0] font-mono text-[10px] font-bold uppercase">
              ×{cluster.count} line{cluster.count === 1 ? "" : "s"} — 1 confirm covers all
            </span>
          </div>
          <div className="font-mono text-[10px] mt-1.5 text-taupe-muted">
            pattern recognition: values templated out · devices: {(cluster.device_ids || []).join(", ") || "—"}
          </div>
          <details className="mt-1.5">
            <summary className="font-mono text-[10px] uppercase tracking-wider text-sprucePine cursor-pointer font-bold">
              Show {Math.min(cluster.examples?.length || 0, 5)} example line{(cluster.examples?.length || 0) === 1 ? "" : "s"}
            </summary>
            <pre className="mt-1.5 max-h-32 overflow-auto font-mono text-[11px] leading-relaxed bg-creamParchment border border-weatheredTaupe rounded p-2">
              {(cluster.examples || []).map((e) => `${e.device_id}:L${e.line_number}: ${e.raw_line}`).join("\n")}
              {(cluster.count || 0) > (cluster.examples || []).length ? `\n…${cluster.count - cluster.examples.length} more` : ""}
            </pre>
          </details>
        </div>
        <div className="text-right shrink-0">
          <div className="label-xs">CompilerAI Proposal</div>
          <div className="font-mono text-xs mt-0.5 font-bold" style={{ color: low ? "var(--warn)" : "var(--pass)" }}>
            {cluster.ai_category || "—"} {cluster.ai_confidence != null && `(${Math.round(cluster.ai_confidence * 100)}%)`}
          </div>
          <div className="font-mono text-[9px] text-taupe-muted mt-0.5">{cluster.ai_source || ""}</div>
        </div>
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <select className="input-field !w-64 !py-1.5 text-xs font-mono" value={selected} onChange={(e) => setSelected(e.target.value)}>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <button disabled={busy} onClick={() => onConfirmCluster(cluster, selected)} className="btn-primary !py-1.5">
          <span className="material-symbols-outlined text-[15px]">done_all</span>
          <span>Confirm pattern (×{cluster.count})</span>
        </button>
      </div>
    </div>
  );
}

function QueueCard({ entry, onConfirm, onReject, busy }) {
  const [selected, setSelected] = useState(entry.ai_category || "unknown");
  const low = entry.ai_confidence != null && entry.ai_confidence < 0.7;

  return (
    <div className="card p-4 border-l-4 border-l-ochreHazard">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="min-w-0">
          <code className="font-mono text-xs px-2 py-1 rounded bg-creamParchment border border-weatheredTaupe text-peatCharcoal block inline-block">
            {entry.raw_line}
          </code>
          <div className="font-mono text-[10px] mt-1.5 text-taupe-muted">
            line {entry.line_number} · device <span className="text-sprucePine font-semibold">{entry.device_id}</span> · {entry.vendor}
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="label-xs">CompilerAI Proposal</div>
          <div className="font-mono text-xs mt-0.5 font-bold" style={{ color: low ? "var(--warn)" : "var(--pass)" }}>
            {entry.ai_category || "—"} {entry.ai_confidence != null && `(${Math.round(entry.ai_confidence * 100)}%)`}
          </div>
          {low && <div className="font-mono text-[9px] uppercase mt-0.5 text-ochreHazard font-bold">Needs human eyes</div>}
        </div>
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <select className="input-field !w-64 !py-1.5 text-xs font-mono" value={selected} onChange={(e) => setSelected(e.target.value)}>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <button disabled={busy} onClick={() => onConfirm(entry, selected)} className="btn-primary !py-1.5">
          <span className="material-symbols-outlined text-[15px]">check</span>
          <span>Confirm Mapping</span>
        </button>
        <button disabled={busy} onClick={() => onReject(entry)} className="btn-ghost !py-1.5">
          <span className="material-symbols-outlined text-[15px] text-terracottaRust">close</span>
          <span>Reject</span>
        </button>
      </div>
      <div className="font-mono text-[9px] text-taupe-muted mt-2 uppercase tracking-wider">
        Confirming stores a normalized pattern so identical future lines auto-match — similar lines still ask.
      </div>
    </div>
  );
}

export default function TrainingLoop() {
  const { data: queueData, loading, reload: reloadQueue } = useApi("/training/queue");
  const { data: mappingData, reload: reloadMappings } = useApi("/training/mappings");
  const { data: vendorData, reload: reloadVendors } = useApi("/training/vendors");
  const { data: decisionData, reload: reloadDecisions } = useApi("/training/decisions?limit=50");
  const [busy, setBusy] = useState(false);
  const [bulkSummaries, setBulkSummaries] = useState({});
  const toast = useToast();

  const queueEntries = queueData?.queue || [];
  // explicit approvals only: unknown proposals can never be bulk-approved
  const approvableByDevice = useMemo(() => {
    const groups = {};
    for (const e of queueEntries) {
      if (!e.ai_category || e.ai_category === "unknown") continue;
      (groups[e.device_id] = groups[e.device_id] || []).push(e);
    }
    return groups;
  }, [queueData]);

  const buildApprovals = (entries, onlyHighConf) =>
    entries
      .filter((e) => !onlyHighConf || (e.ai_confidence ?? 0) >= 0.7)
      .map((e) => ({
        line_number: e.line_number,
        raw_line: e.raw_line,
        category: e.ai_category,
        human_reviewed: false,
      }));

  const bulkDryRun = async (deviceId) => {
    setBusy(true);
    try {
      const res = await api("/training/train-device", {
        method: "POST",
        body: { device_id: deviceId, approvals: buildApprovals(approvableByDevice[deviceId] || [], false), dry_run: true },
      });
      setBulkSummaries((s) => ({ ...s, [deviceId]: res }));
    } catch (e) {
      toast(`Dry-run failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const bulkApproveHighConf = async (deviceId) => {
    setBusy(true);
    try {
      const approvals = buildApprovals(approvableByDevice[deviceId] || [], true);
      if (!approvals.length) {
        toast("No high-confidence proposals for this device — review rows individually.");
        return;
      }
      const res = await api("/training/train-device", {
        method: "POST",
        body: { device_id: deviceId, approvals },
      });
      toast(res.headline || `Approved ${res.trained_lines} lines.`);
      setBulkSummaries((s) => ({ ...s, [deviceId]: null }));
      reloadQueue();
      reloadMappings();
      reloadVendors();
      reloadDecisions();
    } catch (e) {
      toast(`Bulk approve failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const confirm = async (entry, category) => {
    setBusy(true);
    try {
      // identity + proposal provenance are server-derived from the JWT;
      // the client only sends the line, the chosen category, and context.
      const res = await api("/training/confirm", {
        method: "POST",
        body: {
          example_line: entry.raw_line,
          category,
          vendor_hint: entry.vendor || "any",
        },
      });
      toast(`Confirmed: "${entry.raw_line.slice(0, 40)}…" → ${res.mapping.category}. Similar lines now auto-match.`);
      reloadQueue();
      reloadMappings();
      reloadVendors();
      reloadDecisions();
    } catch (e) {
      toast(`Confirm failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const reject = (entry) => toast(`Rejected "${entry.raw_line.slice(0, 40)}" — stays queued for a future reviewer.`);

  const confirmCluster = async (cluster, category) => {
    setBusy(true);
    try {
      const res = await api("/training/confirm", {
        method: "POST",
        body: {
          example_line: cluster.representative_line,
          category,
          vendor_hint: cluster.vendor || "any",
          notes: `bulk pattern confirm ×${cluster.count}`,
        },
      });
      toast(`Pattern confirmed: "${cluster.pattern}" → ${res.mapping.category}. ${cluster.count} line(s) now auto-match.`);
      reloadQueue();
      reloadMappings();
      reloadVendors();
      reloadDecisions();
    } catch (e) {
      toast(`Confirm failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const deleteMapping = async (id) => {
    setBusy(true);
    try {
      await api(`/training/mappings/${id}`, { method: "DELETE" });
      toast("Mapping removed. Lines using it return to the queue.");
      reloadMappings();
      reloadQueue();
      reloadVendors();
      reloadDecisions();
    } finally {
      setBusy(false);
    }
  };

  const revokeVendor = async (vendor) => {
    if (!window.confirm(`Revoke CompilerAI access to '${vendor}'? ${vendorData?.vendors?.find((v) => v.vendor === vendor)?.mappings ?? ""} learned mappings will be removed and its lines return to the queue as unknown.`)) return;
    setBusy(true);
    try {
      const res = await api(`/training/vendors/${encodeURIComponent(vendor)}/revoke`, { method: "POST" });
      toast(`Revoked '${vendor}' — ${res.removed_mappings} mappings removed. CompilerAI no longer recognizes it.`);
      reloadMappings();
      reloadQueue();
      reloadVendors();
      reloadDecisions();
    } catch (e) {
      toast(`Revoke failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const mappings = mappingData?.mappings || [];
  const aiConfirmed = mappings.filter((m) => m.ai_suggested).length;

  return (
    <>
      {/* Banner */}
      <div className="card p-5">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className="w-13 h-13 p-3 rounded-md bg-creamParchment border border-weatheredTaupe flex items-center justify-center text-sprucePine shadow-inner">
              <span className="material-symbols-outlined text-[30px]">psychology</span>
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-display text-xl text-peatCharcoal font-bold tracking-tight">CompilerAI — Human-in-the-Loop Learning</span>
                <span className="px-2 py-0.5 rounded bg-sprucePine text-[#FCF9F0] font-mono text-[10px] font-bold uppercase tracking-wider">CompilerAI</span>
              </div>
              <div className="font-mono text-xs text-taupe-muted mt-2 max-w-2xl leading-relaxed">
                <strong className="text-peatCharcoal">CompilerAI</strong> compiles unknown vendor syntax into known
                categories — but it <strong className="text-peatCharcoal">never issues pass/fail verdicts</strong>. It only proposes
                categories for lines the deterministic parsers couldn't map — a named admin confirms before anything
                enters the learned rule cache. Once trained, the same unknown syntax auto-recognizes on re-ingest.
              </div>
            </div>
          </div>
          <div className="flex gap-6">
            <div className="text-center">
              <div className="font-display text-4xl font-bold text-ochreHazard leading-none">{queueData?.count ?? "—"}</div>
              <div className="label-xs mt-1.5">Pending Review</div>
            </div>
            <div className="text-center">
              <div className="font-display text-4xl font-bold text-peatCharcoal leading-none">{mappings.length}</div>
              <div className="label-xs mt-1.5">Learned Mappings</div>
            </div>
            <div className="text-center">
              <div className="font-display text-4xl font-bold text-mutedMeadow leading-none">{aiConfirmed}</div>
              <div className="label-xs mt-1.5">CompilerAI + Human</div>
            </div>
          </div>
        </div>
      </div>

      {/* Bulk review — explicit approvals only, dry-run first */}
      {Object.keys(approvableByDevice).length > 0 && (
        <section className="card p-4 border-l-4 border-l-sprucePine">
          <div className="label-md mb-1">Bulk Review — explicit per-line approvals</div>
          <div className="font-mono text-[10px] text-taupe-muted mb-3 uppercase tracking-wider">
            Nothing is accepted blindly: preview the summary first, then approve high-confidence lines only.
            Low-confidence and unknown lines stay queued for individual review.
          </div>
          <div className="space-y-2">
            {Object.entries(approvableByDevice).map(([deviceId, entries]) => {
              const high = entries.filter((e) => (e.ai_confidence ?? 0) >= 0.7).length;
              const summary = bulkSummaries[deviceId];
              return (
                <div key={deviceId} className="flex flex-col gap-2 p-2.5 rounded bg-creamParchment border border-weatheredTaupe">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-peatCharcoal">{deviceId}</span>
                    <span className="font-mono text-[10px] text-taupe-muted">
                      {entries.length} approvable · {high} high-confidence · {entries.length - high} need human eyes
                    </span>
                    <span className="flex-1" />
                    <button disabled={busy} onClick={() => bulkDryRun(deviceId)} className="btn-ghost !py-1.5">
                      Preview summary
                    </button>
                    <button disabled={busy} onClick={() => bulkApproveHighConf(deviceId)} className="btn-primary !py-1.5">
                      Approve {high} high-confidence
                    </button>
                  </div>
                  {summary && (
                    <div className="font-mono text-[11px] text-peatCharcoal leading-relaxed">
                      {summary.headline}
                      {Object.keys(summary.per_category || {}).length > 0 && (
                        <span className="text-taupe-muted"> ({Object.entries(summary.per_category).map(([k, v]) => `${k}×${v}`).join(", ")})</span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Pattern clusters — one confirm covers N lines */}
      <section className="space-y-3">
        <div className="label-md flex items-center justify-between">
          <span>Pattern Clusters — one confirm covers every matching line</span>
          {(queueData?.cluster_count ?? 0) > 0 && (
            <span className="font-mono text-[10px] text-taupe-muted">
              {queueData.cluster_count} pattern{(queueData.cluster_count || 0) === 1 ? "" : "s"} from {queueData.count} line{(queueData.count || 0) === 1 ? "" : "s"}
            </span>
          )}
        </div>
        {loading && <div className="font-mono text-xs text-taupe-muted">Clustering patterns…</div>}
        {(queueData?.clusters || []).map((cluster) => (
          <ClusterCard key={cluster.pattern} cluster={cluster} onConfirmCluster={confirmCluster} busy={busy} />
        ))}
        {queueData?.cluster_count === 0 && !loading && (
          <div className="card p-6 font-mono text-xs text-taupe-muted text-center">
            No patterns pending — every line in every ingested config is classified. Ingest an unseen-vendor config to see the loop fire.
          </div>
        )}
      </section>

      {/* Queue */}
      <section className="space-y-3">
        <div className="label-md">Unrecognized Lines Awaiting Review (flat view)</div>
        {loading && <div className="font-mono text-xs text-taupe-muted">Loading queue…</div>}
        {(queueData?.queue || []).map((entry, i) => (
          <QueueCard key={`${entry.device_id}-${entry.line_number}-${i}`} entry={entry} onConfirm={confirm} onReject={reject} busy={busy} />
        ))}
        {queueData?.count === 0 && (
          <div className="card p-6 font-mono text-xs text-taupe-muted text-center">
            Queue empty — every line in every ingested config is classified. Ingest an unseen-vendor config to see the loop fire.
          </div>
        )}
      </section>

      {/* Learned cache */}
      <section className="space-y-3">
        <div className="label-md flex items-center justify-between">
          <span>Learned Rule Cache — Confirmed Mappings</span>
          {mappings.length > 0 && (
            <button
              className="btn-copy"
              onClick={() => copyText(mappings.map((m) => `${m.pattern} -> ${m.category}`).join("\n"), toast, "Mapping cache copied")}
            >
              <span className="material-symbols-outlined text-[14px]">file_copy</span>
              <span>Export Cache</span>
            </button>
          )}
        </div>
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Normalized Pattern</th>
                  <th>Category</th>
                  <th>Origin</th>
                  <th>Matched</th>
                  <th>Confirmed By</th>
                  <th>Confirmed At</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((m) => (
                  <tr key={m.id}>
                    <td className="font-mono text-[11px] text-peatCharcoal">{m.pattern}</td>
                    <td className="font-mono text-[11px]">{m.category}</td>
                    <td>
                      {m.ai_suggested ? (
                          <span className="badge bg-sprucePine text-[#FCF9F0]">COMPILERAI + HUMAN</span>
                      ) : (
                        <span className="status-na">HUMAN</span>
                      )}
                    </td>
                    <td className="font-mono text-[11px]">{m.times_matched}×</td>
                    <td className="font-mono text-[11px]">{m.confirmed_by}</td>
                    <td className="font-mono text-[10px] text-taupe-muted">{m.confirmed_at ? new Date(m.confirmed_at).toLocaleString() : "—"}</td>
                    <td>
                      <button disabled={busy} onClick={() => deleteMapping(m.id)} className="font-mono text-[10px] uppercase font-bold text-terracottaRust hover:underline">
                        remove
                      </button>
                    </td>
                  </tr>
                ))}
                {mappings.length === 0 && (
                  <tr>
                    <td colSpan={7} className="text-center font-mono text-xs text-taupe-muted py-6">
                      No mappings confirmed yet — confirm one from the queue, then watch it auto-match.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="font-mono text-[10px] text-taupe-muted uppercase tracking-wider">
          Deliberate v1 boundary: human-confirmed adaptive mapping cache — not autonomous ML. Only exact
          normalized-pattern hits auto-recognize; similar lines are proposals a human must confirm.
        </div>
      </section>

      {/* Trained vendors — past unknown-vendor trains, revocable */}
      <section className="space-y-3">
        <div className="label-md flex items-center justify-between">
          <span>Trained Vendors — what CompilerAI has learned (revocable)</span>
          {(vendorData?.vendors?.length ?? 0) > 0 && (
            <span className="font-mono text-[10px] text-taupe-muted">
              {vendorData.vendors.length} vendor{(vendorData.vendors.length || 0) === 1 ? "" : "s"} known to CompilerAI
            </span>
          )}
        </div>
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Vendor</th>
                  <th>Learned Mappings</th>
                  <th>Devices Using It</th>
                  <th>Trained By</th>
                  <th>Last Trained</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {(vendorData?.vendors || []).map((v) => (
                  <tr key={v.vendor}>
                    <td className="font-mono text-[11px] font-bold text-peatCharcoal">{v.vendor}</td>
                    <td className="font-mono text-[11px]">{v.mappings}×</td>
                    <td className="font-mono text-[11px]">{(v.device_ids || []).join(", ") || "—"}</td>
                    <td className="font-mono text-[11px]">{(v.reviewers || []).join(", ") || "—"}</td>
                    <td className="font-mono text-[10px] text-taupe-muted">{v.last_trained ? new Date(v.last_trained).toLocaleString() : "—"}</td>
                    <td>
                      <button disabled={busy} onClick={() => revokeVendor(v.vendor)} className="font-mono text-[10px] uppercase font-bold text-terracottaRust hover:underline" title="Remove every learned mapping for this vendor — its lines become unknown again">
                        revoke access
                      </button>
                    </td>
                  </tr>
                ))}
                {(vendorData?.vendors || []).length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center font-mono text-xs text-taupe-muted py-6">
                      No vendor trained yet — train an unseen-vendor config above and it appears here.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="font-mono text-[10px] text-taupe-muted uppercase tracking-wider">
          Revoking removes CompilerAI&apos;s access to that vendor&apos;s syntax — its lines return to the queue as unknown. History is preserved below.
        </div>
      </section>

      {/* Decision log — immutable human-review audit trail */}
      <section className="space-y-3">
        <div className="label-md flex items-center justify-between">
          <span>CompilerAI Decision Log — who confirmed what (immutable)</span>
          {(decisionData?.decisions?.length ?? 0) > 0 && (
            <span className="font-mono text-[10px] text-taupe-muted">
              {decisionData.decisions.length} latest decision{(decisionData.decisions.length || 0) === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Line</th>
                  <th>Decided Category</th>
                  <th>CompilerAI Proposed</th>
                  <th>Decision</th>
                  <th>Reviewer</th>
                  <th>At</th>
                </tr>
              </thead>
              <tbody>
                {(decisionData?.decisions || []).map((d) => (
                  <tr key={d.id}>
                    <td className="font-mono text-[11px] text-peatCharcoal max-w-[280px] truncate" title={d.original_line}>{d.original_line}</td>
                    <td className="font-mono text-[11px]">{d.category}</td>
                    <td className="font-mono text-[10px] text-taupe-muted">{d.proposal_source || "—"}{d.proposal_confidence != null ? ` (${Math.round(d.proposal_confidence * 100)}%)` : ""}</td>
                    <td>
                      <span className={d.decision === "revoked" ? "status-fail" : d.decision.includes("correct") ? "status-error" : "status-pass"}>
                        {d.decision}
                      </span>
                    </td>
                    <td className="font-mono text-[11px]">{d.reviewer}</td>
                    <td className="font-mono text-[10px] text-taupe-muted">{d.decided_at ? new Date(d.decided_at).toLocaleString() : "—"}</td>
                  </tr>
                ))}
                {(decisionData?.decisions || []).length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center font-mono text-xs text-taupe-muted py-6">
                      No human decisions recorded yet — every confirm, correction, and revocation lands here.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </>
  );
}
