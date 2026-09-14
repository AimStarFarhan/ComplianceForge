import { useApi } from "../lib/api";

export default function Footer() {
  const { data } = useApi("/health");
  const online = data?.status === "ok";
  const aiMode =
    data?.ai_mode === "local_lm"
      ? "Local LM (air-gapped)"
      : data?.ai_mode === "llm"
      ? "Cloud LLM"
      : "Deterministic · LLM-ready";

  return (
    <footer className="fixed bottom-0 left-64 right-0 h-10 bg-tacticalOlive border-t border-camoSeam z-30 flex items-center justify-between px-6 text-softSage font-mono text-xs">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5 text-sageMuted">
          <span className="w-2 h-2 rounded-full bg-mutedMeadow animate-ping"></span>
          <span className="text-softSage font-semibold">ENGINE:</span>
          <span>{online ? `Online — ${aiMode}` : "Offline"}</span>
        </div>
        <div className="hidden lg:flex items-center gap-1.5 text-sageMuted">
          <span className="text-camoSeam">|</span>
          <span>Remediation Mode: <strong className="text-softSage">Advisory Only (No Auto-Push)</strong></span>
        </div>
      </div>
      <div className="flex items-center gap-3 text-sageMuted font-mono text-[11px]">
        <span className="px-2 py-0.5 rounded bg-olivePanel text-softSage border border-camoSeam">CONFIDENTIAL</span>
        <span>© 2026 ComplianceForge</span>
      </div>
    </footer>
  );
}
