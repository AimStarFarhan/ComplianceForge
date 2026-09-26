import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { api } from "./api";
import { useToast } from "../components/Toast";

/**
 * Global ingest/audit job store. Lives above the router so jobs keep
 * running — and stay visible — while the user navigates to Dashboard,
 * Devices, Training, etc. Each file pipelines ingest → audit on its own,
 * with a small worker pool so local SQLite isn't thrashed by lock contention.
 */

const JobsCtx = createContext(null);
export const useJobs = () => useContext(JobsCtx);

const MAX_JOBS = 12;
const POOL = 3;
const ACTIVE = ["queued", "uploading", "normalized", "auditing"];

async function pool(tasks, n) {
  const out = new Array(tasks.length);
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(n, tasks.length)) }, async () => {
    while (i < tasks.length) {
      const k = i++;
      try {
        out[k] = { ok: true, v: await tasks[k]() };
      } catch (e) {
        out[k] = { ok: false, e };
      }
    }
  });
  await Promise.all(workers);
  return out;
}

export function JobsProvider({ children }) {
  const [jobs, setJobs] = useState([]);
  const toast = useToast();

  const patch = useCallback(
    (key, p) => setJobs((prev) => prev.map((j) => (j.key === key ? { ...j, ...p } : j))),
    []
  );

  // One file, fully pipelined: ingest, then immediately its own audit.
  const runFile = useCallback(
    async (job) => {
      patch(job.key, { stage: "uploading" });
      let res;
      try {
        const fd = new FormData();
        fd.append("file", job.file);
        if (job.explicitDeviceId) fd.append("device_id", job.explicitDeviceId);
        if (job.vendor && job.vendor !== "auto") fd.append("vendor", job.vendor);
        res = await api("/ingest", { method: "POST", files: fd });
      } catch (e) {
        patch(job.key, { stage: "error", error: `Ingest failed: ${e.message}` });
        return { error: e };
      }
      patch(job.key, { stage: "normalized", ...res });
      if (res.next_step === "train") {
        patch(job.key, { stage: "train", unparsed_count: res.unparsed_count });
        return { res, needsTrain: true };
      }
      patch(job.key, { stage: "auditing" });
      try {
        const a = await api(`/audit/${encodeURIComponent(res.device_id)}`, { method: "POST" });
        patch(job.key, { stage: "scored", audit: a.summary });
        return { res, audit: a.summary };
      } catch (e) {
        patch(job.key, { stage: "error", error: `Audit failed: ${e.message}` });
        return { error: e };
      }
    },
    [patch]
  );

  const startIngest = useCallback(
    async (files, { deviceId = "", vendor = "auto" } = {}) => {
      const batch = files.map((f, i) => ({
        key: `${f.name}-${i}-${Date.now()}`,
        file: f,
        name: f.name,
        stage: "queued",
        vendor: "",
        explicitDeviceId: deviceId && files.length === 1 ? deviceId : "",
      }));
      setJobs((prev) => [...batch, ...prev].slice(0, MAX_JOBS));
      // let the queued lanes paint before the pool starts them
      await new Promise((r) => setTimeout(r, 30));
      const results = await pool(
        batch.map((j) => () => runFile(j)),
        POOL
      );
      const ok = results.filter((r) => r.ok && r.v?.res).length;
      const scored = results.filter((r) => r.ok && r.v?.audit).length;
      const train = results.filter((r) => r.ok && r.v?.needsTrain).length;
      // one assistant nudge for the whole batch — not one per file
      const lastAudit = results.map((r) => (r.ok ? r.v : null)).find((v) => v?.audit);
      if (lastAudit) {
        window.dispatchEvent(
          new CustomEvent("cf:audited", {
            detail: { deviceId: lastAudit.res.device_id, summary: lastAudit.audit },
          })
        );
      }
      if (files.length === 1) {
        const s = results[0];
        if (!s.ok || s.v?.error) {
          toast(`Ingest failed: ${s.e?.message || s.v?.error?.message}`);
        } else if (s.v?.needsTrain) {
          toast(`Unknown vendor detected — ${s.v.res.unparsed_count} lines ready to train`);
        } else {
          toast(`Scored ${s.v.res.hostname || s.v.res.device_id} — ${s.v.res.vendor_label}`);
        }
      } else {
        toast(
          `Parallel run: ${ok}/${batch.length} ingested, ${scored} scored` +
            (train ? `, ${train} need training` : "")
        );
      }
    },
    [runFile, toast]
  );

  const clearFinished = useCallback(
    () => setJobs((prev) => prev.filter((j) => ACTIVE.includes(j.stage))),
    []
  );

  const value = useMemo(
    () => ({ jobs, startIngest, clearFinished, ACTIVE }),
    [jobs, startIngest, clearFinished]
  );

  return <JobsCtx.Provider value={value}>{children}</JobsCtx.Provider>;
}
