import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useToast } from "../components/Toast";

const VENDOR_HINTS = [
  ["auto", "Auto-detect (syntax fingerprints)"],
  ["cisco_ios", "Cisco IOS / IOS-XE"],
  ["juniper_srx", "Juniper SRX (JunOS)"],
  ["sonic", "SONiC (config DB JSON)"],
];

export default function UploadIngest() {
  const [files, setFiles] = useState([]);
  const [deviceId, setDeviceId] = useState("");
  const [vendor, setVendor] = useState("auto");
  const [result, setResult] = useState(null);
  const [bulkResults, setBulkResults] = useState([]);
  const [busy, setBusy] = useState(false);
  const [trainMsg, setTrainMsg] = useState("");
  const toast = useToast();

  const ingestOne = async (file, idx, total) => {
    const fd = new FormData();
    fd.append("file", file);
    // single-file mode may carry an explicit device id; bulk defaults to hostname/filename
    if (deviceId && total === 1) fd.append("device_id", deviceId);
    if (vendor !== "auto") fd.append("vendor", vendor);
    return api("/ingest", { method: "POST", files: fd });
  };

  const ingest = async () => {
    if (!files.length) return;
    setBusy(true);
    setResult(null);
    setBulkResults([]);
    setTrainMsg("");
    try {
      const outs = [];
      for (let i = 0; i < files.length; i++) {
        try {
          const res = await ingestOne(files[i], i, files.length);
          outs.push({ file: files[i].name, ok: true, ...res });
        } catch (e) {
          outs.push({ file: files[i].name, ok: false, error: e.message });
        }
      }
      setBulkResults(outs);
      const firstOk = outs.find((o) => o.ok);
      if (firstOk) setResult(firstOk);
      const okCount = outs.filter((o) => o.ok).length;
      const trainCount = outs.filter((o) => o.ok && o.next_step === "train").length;
      if (files.length === 1) {
        const res = firstOk;
        if (!res) {
          toast(`Ingest failed: ${outs[0]?.error}`);
        } else if (res.next_step === "train") {
          toast(`Unknown vendor detected — ${res.unparsed_count} lines ready to train`);
        } else if (res.next_step === "recognized_unknown") {
          toast("This file is now KNOWN — every line auto-recognized. Run the audit.");
        } else {
          toast(`Ingest complete — ${res.vendor_label} normalized, ${res.unparsed_count} lines queued`);
        }
      } else {
        toast(`Bulk ingest: ${okCount}/${outs.length} files normalized${trainCount ? `, ${trainCount} need training` : ""}`);
      }
    } finally {
      setBusy(false);
    }
  };

  const trainDevice = async () => {
    if (!result) return;
    setBusy(true);
    try {
      const res = await api("/training/train-device", {
        method: "POST",
        body: { device_id: result.device_id, confirmed_by: "admin" },
      });
      setTrainMsg(
        `Trained ${res.trained_lines} lines (${res.already_learned} already known). ` +
        `This vendor is now KNOWN — re-ingest the same file or run the audit; all lines auto-recognize and full rule checks apply.`
      );
      toast(`Device trained — ${res.trained_lines} mappings confirmed. Vendor is now known.`);
      // refresh ingest state for this device
      const fresh = { ...result, next_step: "recognized_unknown", trainable: false, fully_recognized: true, recognized_count: res.trained_lines + res.already_learned };
      setResult(fresh);
    } catch (e) {
      toast(`Training failed: ${e.message}`);
    } finally {
      setBusy(false);
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
              onChange={(e) => setFiles(Array.from(e.target.files || []))}
              className="w-full text-sm px-3 py-2 rounded-md bg-sandstoneLight border border-weatheredTaupe text-peatCharcoal file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-sprucePine file:text-[#FCF9F0] file:font-semibold file:text-xs"
            />
            {files.length > 1 && (
              <div className="font-mono text-[11px] text-sprucePine mt-1.5 font-semibold">
                {files.length} files selected — bulk ingest normalizes each to its own device.
              </div>
            )}
          </div>
          <div>
            <label className="label-md block mb-1.5">Vendor</label>
            <select className="input-field font-mono text-xs" value={vendor} onChange={(e) => setVendor(e.target.value)}>
              {VENDOR_HINTS.map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label-md block mb-1.5">Device ID (optional — single-file only; bulk defaults to hostname or filename)</label>
            <input className="input-field font-mono text-xs" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="e.g. core-rtr-mum-01" />
          </div>
          <button onClick={ingest} disabled={!files.length || busy} className="btn-primary w-full justify-center !py-2.5">
            <span className="material-symbols-outlined text-[17px]">{busy ? "hourglass_top" : "upload_file"}</span>
            <span>{busy ? "Normalizing to baseline…" : files.length > 1 ? `Ingest & Normalize (${files.length} files)` : "Ingest & Normalize"}</span>
          </button>
          <div className="font-mono text-[10px] text-taupe-muted leading-relaxed pt-2 border-t border-weatheredTaupe">
            Sample fixtures live in <code className="text-sprucePine">backend/sample_configs/</code> — compliant + noncompliant
            per vendor. Unrecognized syntax (any vendor) auto-routes to the Training Loop as <strong>unseen_vendor</strong>.
          </div>
        </div>

        {/* Result pane */}
        <div className="lg:col-span-7">
          {result ? (
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
                      <span className="font-display text-lg font-bold text-peatCharcoal">{result.hostname || result.device_id}</span>
                      <span className="pill-device">{result.vendor_label}</span>
                      {result.vendor !== result.detected_vendor && (
                        <span className="pill-meta">detected: {result.detected_vendor}</span>
                      )}
                    </div>
                    <div className="font-mono text-[11px] text-taupe-muted mt-1">
                      {result.os_version ? `OS ${result.os_version}` : "OS fingerprint n/a"}
                      {result.model ? ` · ${result.model}` : ""} · snapshot #{result.snapshot_id}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Link to={`/console/devices/${encodeURIComponent(result.device_id)}`} className="btn-primary !py-1.5">Open Device →</Link>
                    <Link to="/console/training" className="btn-ghost !py-1.5">Training Queue ({result.unparsed_count})</Link>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="pane p-3">
                    <div className="font-display text-2xl font-bold text-ochreHazard">{result.unparsed_count}</div>
                    <div className="label-xs mt-1">Lines to training queue</div>
                  </div>
                  <div className="pane p-3">
                    <div className="font-display text-2xl font-bold text-sprucePine">{result.unparsed_count === 0 ? "FULL" : "PARTIAL"}</div>
                    <div className="label-xs mt-1">Parser coverage</div>
                  </div>
                  <div className="pane p-3">
                    <div className="font-display text-2xl font-bold text-peatCharcoal truncate">{result.vendor}</div>
                    <div className="label-xs mt-1">Parser selected</div>
                  </div>
                </div>

                {/* UNKNOWN-VENDOR flow states */}
                {result.is_unknown_vendor && result.next_step === "train" && (
                  <div className="p-4 rounded-lg bg-ochreWash border-2 border-ochreHazard/50">
                    <div className="flex items-start gap-3">
                      <span className="material-symbols-outlined text-[26px] text-ochreHazard">psychology_alt</span>
                      <div className="flex-1">
                        <div className="font-display text-sm font-bold text-peatCharcoal">
                          Unknown vendor — {result.unparsed_count} unrecognized lines
                        </div>
                        <div className="font-mono text-[11px] text-taupe-muted mt-1 leading-relaxed">
                          No parser knows this syntax yet. Every line is queued with an AI-proposed category.
                          Train on this data to make this vendor <strong className="text-peatCharcoal">known</strong> — after training,
                          re-ingesting this file auto-recognizes every line and full audit tests run on it.
                        </div>
                        <div className="flex items-center gap-2 mt-3">
                          <button onClick={trainDevice} disabled={busy} className="btn-primary">
                            <span className="material-symbols-outlined text-[17px]">model_training</span>
                            <span>{busy ? "Training…" : "Train on this data"}</span>
                          </button>
                          <Link to="/console/training" className="btn-ghost">
                            <span className="material-symbols-outlined text-[17px]">rate_review</span>
                            <span>Review line-by-line</span>
                          </Link>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {result.is_unknown_vendor && result.next_step === "recognized_unknown" && (
                  <div className="p-4 rounded-lg bg-meadowWash border-2 border-mutedMeadow/50">
                    <div className="flex items-start gap-3">
                      <span className="material-symbols-outlined text-[26px] text-mutedMeadow">verified</span>
                      <div className="flex-1">
                        <div className="font-display text-sm font-bold text-peatCharcoal">
                          Vendor now KNOWN — {result.recognized_count ?? result.unparsed_count} lines auto-recognized
                        </div>
                        <div className="font-mono text-[11px] text-taupe-muted mt-1 leading-relaxed">
                          Previously-trained mappings matched every line in this file. Full rule checks now apply —
                          run the audit.
                        </div>
                        <Link to={`/console/devices/${encodeURIComponent(result.device_id)}`} className="btn-primary mt-3">
                          <span className="material-symbols-outlined text-[17px]">play_arrow</span>
                          <span>Run Audit on this device</span>
                        </Link>
                      </div>
                    </div>
                  </div>
                )}

                {trainMsg && (
                  <div className="p-3 rounded bg-creamParchment border border-weatheredTaupe font-mono text-xs text-peatCharcoal leading-relaxed">
                    <span className="material-symbols-outlined text-[15px] text-mutedMeadow align-middle mr-1.5">model_training</span>
                    {trainMsg}
                  </div>
                )}

                {result.unparsed_lines?.length > 0 && (
                  <details className="pane p-3">
                    <summary className="label-md cursor-pointer">Unrecognized lines (queued for human review)</summary>
                    <pre className="mt-2 max-h-56 overflow-auto font-mono text-[11px] leading-relaxed">
                      {result.unparsed_lines.map((l) => `L${l.line_number}: ${l.text}`).join("\n")}
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
          {bulkResults.length > 1 && (
            <div className="card overflow-hidden mt-4">
              <div className="px-3 py-2 bg-creamParchment border-b border-weatheredTaupe font-display text-xs font-bold text-peatCharcoal">
                Bulk ingest — {bulkResults.filter((r) => r.ok).length}/{bulkResults.length} normalized
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Device</th>
                    <th>Vendor</th>
                    <th>Queued</th>
                    <th>Next</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {bulkResults.map((r, i) => (
                    <tr key={`${r.file}-${i}`}>
                      <td className="font-mono text-[11px]">{r.file}</td>
                      {r.ok ? (
                        <>
                          <td className="font-mono text-[11px]">{r.hostname || r.device_id}</td>
                          <td className="font-mono text-[11px]">{r.vendor_label || r.vendor}</td>
                          <td className="font-mono text-[11px]">{r.unparsed_count}</td>
                          <td className="font-mono text-[11px] font-bold">{r.next_step}</td>
                          <td>
                            <Link to={`/console/devices/${encodeURIComponent(r.device_id)}`} className="font-mono text-[10px] uppercase font-bold text-sprucePine hover:underline">
                              open →
                            </Link>
                          </td>
                        </>
                      ) : (
                        <>
                          <td colSpan={4} className="font-mono text-[11px] text-terracottaRust">{r.error}</td>
                          <td></td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
