import { useMemo, useState } from "react";
import { api, useApi } from "../lib/api";
import { useToast, copyText } from "../components/Toast";

const CATEGORIES = [
  "management_protocol", "ssh_policy", "authentication", "aaa", "password_policy",
  "logging", "syslog", "access_control", "acl_logging", "cryptography",
  "snmp_management", "ntp", "service_hardening", "banner", "privilege_escalation",
  "routing_integrity", "interface_security", "zone_policy", "unknown",
];

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
          <div className="label-xs">AI Proposal</div>
          <div className="font-mono text-xs mt-0.5 font-bold" style={{ color: low ? "#C27803" : "#2D6A4F" }}>
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
        Confirming stores a normalized pattern so similar future lines auto-match — no re-asking.
      </div>
    </div>
  );
}

export default function TrainingLoop() {
  const { data: queueData, loading, reload: reloadQueue } = useApi("/training/queue");
  const { data: mappingData, reload: reloadMappings } = useApi("/training/mappings");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const confirm = async (entry, category) => {
    setBusy(true);
    try {
      const res = await api("/training/confirm", {
        method: "POST",
        body: {
          example_line: entry.raw_line,
          category,
          confirmed_by: "admin",
          ai_suggested: Boolean(entry.ai_category) && entry.ai_category === category,
          ai_confidence: entry.ai_confidence ?? null,
          vendor_hint: entry.vendor || "any",
        },
      });
      toast(`Confirmed: "${entry.raw_line.slice(0, 40)}…" → ${res.mapping.category}. Similar lines now auto-match.`);
      reloadQueue();
      reloadMappings();
    } catch (e) {
      toast(`Confirm failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const reject = (entry) => toast(`Rejected "${entry.raw_line.slice(0, 40)}" — stays queued for a future reviewer.`);

  const deleteMapping = async (id) => {
    setBusy(true);
    try {
      await api(`/training/mappings/${id}`, { method: "DELETE" });
      toast("Mapping removed. Lines using it return to the queue.");
      reloadMappings();
      reloadQueue();
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
                <span className="font-display text-xl text-peatCharcoal font-bold tracking-tight">Human-in-the-Loop Adaptive Learning</span>
                <span className="px-2 py-0.5 rounded bg-sprucePine text-white font-mono text-[10px] font-bold uppercase tracking-wider">Adaptive AI</span>
              </div>
              <div className="font-mono text-xs text-taupe-muted mt-2 max-w-2xl leading-relaxed">
                The AI layer <strong className="text-peatCharcoal">never issues pass/fail verdicts</strong>. It only proposes
                categories for lines the deterministic parsers couldn't map — a named admin confirms before anything
                enters the learned rule cache.
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
              <div className="label-xs mt-1.5">AI + Human-Confirmed</div>
            </div>
          </div>
        </div>
      </div>

      {/* Queue */}
      <section className="space-y-3">
        <div className="label-md">Unrecognized Lines Awaiting Review</div>
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
                        <span className="badge bg-sprucePine text-white">AI + HUMAN</span>
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
          Deliberate v1 boundary: human-confirmed adaptive mapping cache — not autonomous ML. Auto-match threshold 0.82 similarity on normalized patterns.
        </div>
      </section>
    </>
  );
}
