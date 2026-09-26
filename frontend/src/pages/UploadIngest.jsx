import { useState } from "react";
import { Link } from "react-router-dom";
import { useJobs } from "../lib/jobs";

const VENDOR_HINTS = [
  ["auto", "Auto-detect (syntax fingerprints)"],
  ["cisco_ios", "Cisco IOS / IOS-XE"],
  ["juniper_srx", "Juniper SRX (JunOS)"],
  ["sonic", "SONiC (config DB JSON)"],
];

// Lane stage machine: queued → uploading → normalized → auditing → scored
// Side exits: train (unknown vendor, needs human) / error (ingest or audit failed)
const STAGE_PCT = { queued: 5, uploading: 25, normalized: 50, auditing: 75, scored: 100, train: 100, error: 100 };
const STAGE_LABEL = {
  queued: "Queued", uploading: "Uploading", normalized: "Normalized",
  auditing: "Auditing", scored: "Scored", train: "Needs training", error: "Failed",
};

function LaneCard({ lane }) {
  const steps = ["uploading", "normalized", "auditing", "scored"];
  const order = { queued: -1, uploading: 0, normalized: 1, auditing: 2, scored: 3, train: 2, error: -2 };
  const done = lane.stage === "scored" || lane.stage === "train";
  const failed = lane.stage === "error";
  const pct = STAGE_PCT[lane.stage] ?? 0;
  const score = lane.audit?.compliance_pct;
  return (
    <div className="card p-4 flex flex-col gap-3 min-w-0">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="font-mono text-xs font-bold text-peatCharcoal truncate" title={lane.name}>{lane.name}</div>
          <div className="font-mono text-[10px] text-taupe-muted mt-0.5">
            {lane.vendor_label || lane.vendor || (failed ? "—" : "detecting vendor…")}
          </div>
        </div>
        <span
          className="shrink-0 font-mono text-[10px] font-bold uppercase px-2 py-0.5 rounded"
          style={{
            background: failed ? "var(--fail-wash)" : done ? "var(--pass-wash)" : "var(--pane-deep)",
            color: failed ? "var(--fail)" : done ? "var(--pass)" : "var(--ink-soft)",
            border: "1px solid var(--line)",
          }}
        >
          {STAGE_LABEL[lane.stage]}
        </span>
      </div>

      {/* stage stepper */}
      <div className="flex items-center gap-1">
        {steps.map((s, i) => {
          const reached = order[lane.stage] >= i && !failed;
          const isTrainExit = lane.stage === "train" && i === 2;
          return (
            <div key={s} className="flex-1 flex items-center gap-1">
              <div
                className="h-1.5 flex-1 rounded-full"
                style={{ background: reached || isTrainExit ? "var(--pass)" : "var(--line-soft)" }}
              />
              {i < steps.length - 1 && <div className="w-1" />}
            </div>
          );
        })}
      </div>

      {/* progress + score */}
      <div className="flex items-center justify-between">
        <div className="w-full bg-[var(--pane-deep)] h-1.5 rounded-full overflow-hidden border border-[var(--line-soft)]">
          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: failed ? "var(--fail)" : "var(--accent)" }} />
        </div>
        {score !== undefined && score !== null && (
          <span className="ml-2 font-display text-lg font-bold text-peatCharcoal shrink-0">{score}%</span>
        )}
      </div>
      {lane.audit && (
        <div className="font-mono text-[10px] text-taupe-muted">
          {lane.audit.pass_count} pass · {lane.audit.fail_count} fail · {lane.audit.total_rules} rules
          {lane.audit.provisional ? " · provisional" : ""}
        </div>
      )}
      {lane.stage === "train" && (
        <div className="font-mono text-[10px] text-ochreHazard leading-relaxed">
          Unknown syntax — {lane.unparsed_count} lines queued, other lanes not blocked.
        </div>
      )}
      {failed && <div className="font-mono text-[10px] text-terracottaRust leading-relaxed">{lane.error}</div>}

      {/* per-lane actions */}
      <div className="flex items-center gap-2 mt-auto pt-1">
        {lane.device_id && (
          <Link to={`/console/devices/${encodeURIComponent(lane.device_id)}`} className="btn-ghost !py-1 !text-[11px]">
            {lane.stage === "scored" ? "View report →" : "Open device →"}
          </Link>
        )}
        {lane.stage === "train" && (
          <Link to="/console/training" className="btn-primary !py-1 !text-[11px]">
            Train ({lane.unparsed_count})
          </Link>
        )}
      </div>
    </div>
  );
}

export default function UploadIngest() {
  const [files, setFiles] = useState([]);
  const [deviceId, setDeviceId] = useState("");
  const [vendor, setVendor] = useState("auto");
  const [running, setRunning] = useState(false);
  const { jobs, startIngest, clearFinished, ACTIVE } = useJobs();

  const activeCount = jobs.filter((j) => ACTIVE.includes(j.stage)).length;
  const finishedCount = jobs.length - activeCount;
  // single-file detail pane reads the one global job — it survives navigation
  const solo = jobs.length === 1 ? jobs[0] : null;
  const showLanes = jobs.length > 1 || (!solo && jobs.length === 1);

  const ingest = async () => {
    if (!files.length || running) return;
    setRunning(true);
    try {
      await startIngest(files, { deviceId, vendor });
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <div className="flex items-center gap-2.5">
        <span className="material-symbols-outlined text-sprucePine text-[24px]">add_circle</span>
        <div>
          <span className="font-display text-base font-bold text-peatCharcoal">Ingest Raw Configuration</span>
          <span className="font-sans text-xs text-taupe-muted block">Static file upload only — no live SSH polling (v1 boundary by design)</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Upload form */}
        <div className="lg:col-span-5 card p-5 space-y-4">
          <div>
            <label className="label-md block mb-1.5">Config Files — single or bulk (.cfg / .txt / .json)</label>
            <input
              type="file"
              multiple
              accept=".cfg,.txt,.json,.log,.conf"
              disabled={running}
              onChange={(e) => setFiles(Array.from(e.target.files || []))}
              className="w-full text-sm px-3 py-2 rounded-md bg-sandstoneLight border border-weatheredTaupe text-peatCharcoal file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-sprucePine file:text-[#FCF9F0] file:font-semibold file:text-xs"
            />
            {files.length > 1 && (
              <div className="font-mono text-[11px] text-sprucePine mt-1.5 font-semibold">
                {files.length} files selected — each gets its own parallel lane: ingest → audit.
              </div>
            )}
          </div>
          <div>
            <label className="label-md block mb-1.5">Vendor</label>
            <select className="input-field font-mono text-xs" value={vendor} onChange={(e) => setVendor(e.target.value)} disabled={running}>
              {VENDOR_HINTS.map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label-md block mb-1.5">Device ID (optional — single-file only; bulk defaults to hostname or filename)</label>
            <input className="input-field font-mono text-xs" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="e.g. core-rtr-mum-01" disabled={running} />
          </div>
          <button onClick={ingest} disabled={!files.length || running} className="btn-primary w-full justify-center !py-2.5">
            <span className="material-symbols-outlined text-[17px]">{running || activeCount ? "hourglass_top" : "upload_file"}</span>
            <span>
              {running || activeCount
                ? `Running in parallel… (${finishedCount}/${jobs.length})`
                : files.length > 1
                  ? `Ingest & Audit (${files.length} files, parallel)`
                  : "Ingest & Audit"}
            </span>
          </button>
          <div className="font-mono text-[10px] text-taupe-muted leading-relaxed pt-2 border-t border-weatheredTaupe">
            Sample fixtures live in <code className="text-sprucePine">backend/sample_configs/</code> — compliant + noncompliant
            per vendor. Unrecognized syntax (any vendor) auto-routes to the Training Loop as <strong>unseen_vendor</strong> without
            blocking the lanes that already scored. Jobs keep running if you navigate away — watch them in the left sidebar.
          </div>
        </div>

        {/* Result pane */}
        <div className="lg:col-span-7">
          {showLanes ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {jobs.map((lane) => (
                <LaneCard key={lane.key} lane={lane} />
              ))}
              {jobs.length === 0 && (
                <div className="card p-8 flex flex-col items-center justify-center gap-3 min-h-[300px] md:col-span-2">
                  <span className="material-symbols-outlined text-[44px] text-weatheredTaupe">cloud_upload</span>
                  <div className="font-mono text-xs text-taupe-muted uppercase tracking-wider text-center">
                    Select files to open one parallel lane per file here.
                  </div>
                </div>
              )}
              {finishedCount > 0 && (
                <div className="md:col-span-2 flex justify-end">
                  <button onClick={clearFinished} className="btn-ghost !py-1.5">Clear finished ({finishedCount})</button>
                </div>
              )}
            </div>
          ) : solo?.device_id ? (
            <div className="card overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 bg-creamParchment border-b border-weatheredTaupe">
                <span className="font-display text-xs font-bold text-peatCharcoal">Ingest Result — Vendor-Neutral Baseline</span>
                <div className="flex items-center gap-1.5 text-taupe-muted font-mono text-[11px]">
                  <span className="w-2 h-2 rounded-full bg-mutedMeadow"></span>
                  <span>Parser OK</span>
                </div>
              </div>
              <div className="p-4 space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-display text-lg font-bold text-peatCharcoal">{solo.hostname || solo.device_id}</span>
                      <span className="pill-device">{solo.vendor_label}</span>
                      {solo.vendor !== solo.detected_vendor && (
                        <span className="pill-meta">detected: {solo.detected_vendor}</span>
                      )}
                    </div>
                    <div className="font-mono text-[11px] text-taupe-muted mt-1">
                      {solo.os_version ? `OS ${solo.os_version}` : "OS fingerprint n/a"}
                      {solo.model ? ` · ${solo.model}` : ""} · snapshot #{solo.snapshot_id}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Link to={`/console/devices/${encodeURIComponent(solo.device_id)}`} className="btn-primary !py-1.5">Open Device →</Link>
                    <Link to="/console/training" className="btn-ghost !py-1.5">Training Queue ({solo.unparsed_count})</Link>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="pane p-3">
                    <div className="font-display text-2xl font-bold text-ochreHazard">{solo.unparsed_count}</div>
                    <div className="label-xs mt-1">Lines to training queue</div>
                  </div>
                  <div className="pane p-3">
                    <div className="font-display text-2xl font-bold text-sprucePine">{solo.unparsed_count === 0 ? "FULL" : "PARTIAL"}</div>
                    <div className="label-xs mt-1">Parser coverage</div>
                  </div>
                  <div className="pane p-3">
                    <div className="font-display text-2xl font-bold text-peatCharcoal truncate">{solo.vendor}</div>
                    <div className="label-xs mt-1">Parser selected</div>
                  </div>
                </div>

                {solo.audit && (
                  <div className="pane p-3 flex items-center gap-4">
                    <div>
                      <div className="font-display text-2xl font-bold text-peatCharcoal">{solo.audit.compliance_pct}%</div>
                      <div className="label-xs mt-1">Compliance score</div>
                    </div>
                    <div className="font-mono text-[11px] text-taupe-muted">
                      {solo.audit.pass_count} pass · {solo.audit.fail_count} fail · {solo.audit.total_rules} rules
                      {solo.audit.provisional ? " · provisional" : ""}
                    </div>
                    <span className="flex-1" />
                    <Link to={`/console/devices/${encodeURIComponent(solo.device_id)}`} className="btn-primary !py-1.5">View report →</Link>
                  </div>
                )}

                {/* UNKNOWN-VENDOR flow states */}
                {solo.is_unknown_vendor && solo.stage === "train" && (
                  <div className="p-4 rounded-lg bg-ochreWash border-2 border-ochreHazard/50">
                    <div className="flex items-start gap-3">
                      <span className="material-symbols-outlined text-[26px] text-ochreHazard">psychology_alt</span>
                      <div className="flex-1">
                        <div className="font-display text-sm font-bold text-peatCharcoal">
                          Unknown vendor — {solo.unparsed_count} unrecognized lines found
                        </div>
                        <div className="font-mono text-[11px] text-taupe-muted mt-1 leading-relaxed">
                          No parser knows this syntax yet. Every line was queued with a proposed category.
                          Review and approve lines in the Training Queue to make this vendor <strong className="text-peatCharcoal">known</strong> — after training,
                          re-ingesting this file auto-recognizes every line and full audit tests run on it.
                        </div>
                        <div className="flex items-center gap-2 mt-3">
                          <Link to="/console/training" className="btn-primary">
                            <span className="material-symbols-outlined text-[17px]">model_training</span>
                            <span>Review & approve ({solo.unparsed_count} lines)</span>
                          </Link>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {solo.next_step === "recognized_unknown" && (
                  <div className="p-4 rounded-lg bg-meadowWash border-2 border-mutedMeadow/50">
                    <div className="flex items-start gap-3">
                      <span className="material-symbols-outlined text-[26px] text-mutedMeadow">verified</span>
                      <div className="flex-1">
                        <div className="font-display text-sm font-bold text-peatCharcoal">
                          Vendor now KNOWN — {solo.recognized_count ?? solo.unparsed_count} lines auto-recognized
                        </div>
                        <div className="font-mono text-[11px] text-taupe-muted mt-1 leading-relaxed">
                          Previously-trained mappings matched every line in this file. Full rule checks now apply —
                          run the audit.
                        </div>
                        <Link to={`/console/devices/${encodeURIComponent(solo.device_id)}`} className="btn-primary mt-3">
                          <span className="material-symbols-outlined text-[17px]">play_arrow</span>
                          <span>Run Audit on this device</span>
                        </Link>
                      </div>
                    </div>
                  </div>
                )}

                {solo.unparsed_lines?.length > 0 && (
                  <details className="pane p-3">
                    <summary className="label-md cursor-pointer">Unrecognized lines — AI proposals queued for human review</summary>
                    <pre className="mt-2 max-h-56 overflow-auto font-mono text-[11px] leading-relaxed">
                      {solo.unparsed_lines.map((l) => `L${l.line_number}: ${l.text}${l.suggested_category ? `  → AI: ${l.suggested_category} (${Math.round((l.suggested_confidence ?? 0) * 100)}%, ${l.suggested_source || l.match_type || "proposal"})` : ""}`).join("\n")}
                    </pre>
                  </details>
                )}
              </div>
              <div className="px-4 py-2 bg-warm-sandstone border-t border-weatheredTaupe flex items-center justify-between text-taupe-muted font-mono text-[11px]">
                <span>Next step: open the device and RUN AUDIT</span>
                <span className="text-mutedMeadow font-semibold">Baseline normalized to security-baseline v1</span>
              </div>
            </div>
          ) : (
            <div className="card p-8 flex flex-col items-center justify-center gap-3 min-h-[300px]">
              <span className="material-symbols-outlined text-[44px] text-weatheredTaupe">cloud_upload</span>
              <div className="font-mono text-xs text-taupe-muted uppercase tracking-wider text-center">
                Select one or more config files to preview ingest results here.
                <br />
                Vendor is auto-detected per file from syntax fingerprints.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
