import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";

const QUICK_PROMPTS = [
  { label: "Report summary", question: "Give me a summary of this audit report." },
  { label: "What failed?", question: "Which tests failed and why?" },
  { label: "How do I fix everything?", question: "Explain step by step how I can fix every failed test so the next audit passes." },
  { label: "What passed?", question: "Which tests passed?" },
];

function rendered(text) {
  // minimal markdown: headings, bold, code blocks, bullets
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const blocks = text.split(/```/);
  return blocks.map((block, i) => {
    if (i % 2 === 1) {
      return (
        <pre key={i} className="code-pane my-2 text-xs">
          {block.replace(/^\w*\n/, "")}
        </pre>
      );
    }
    const lines = block.split("\n").map((ln, j) => {
      let out = esc(ln);
      out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      out = out.replace(/`([^`]+)`/g, '<code class="px-1 rounded bg-[var(--pane)] font-mono text-[11px]">$1</code>');
      out = out.replace(/_([^_]+)_/g, "<em>$1</em>");
      if (/^### /.test(ln)) return <h4 key={j} className="font-display text-sm font-bold mt-2" dangerouslySetInnerHTML={{ __html: out.replace(/^### /, "") }} />;
      if (/^## /.test(ln)) return <h3 key={j} className="font-display text-sm font-bold mt-2 mb-1" dangerouslySetInnerHTML={{ __html: out.replace(/^## /, "") }} />;
      if (/^- /.test(ln)) return <li key={j} className="ml-4 list-disc" dangerouslySetInnerHTML={{ __html: out.replace(/^- /, "") }} />;
      if (/^\s*$/.test(ln)) return <div key={j} className="h-2" />;
      return <p key={j} className="leading-relaxed" dangerouslySetInnerHTML={{ __html: out }} />;
    });
    return <div key={i}>{lines}</div>;
  });
}

function Bubble({ role, text, source }) {
  const isUser = role === "user";
  return (
    <div className={`flex gap-2.5 ${isUser ? "flex-row-reverse" : ""} chat-msg-in`}>
      <div
        className="w-7 h-7 shrink-0 rounded-md flex items-center justify-center text-[#FCF9F0] font-bold font-mono text-[11px]"
        style={{ background: isUser ? "var(--accent)" : "var(--pass)" }}
      >
        {isUser ? "YOU" : "AI"}
      </div>
      <div
        className={`max-w-[85%] rounded-lg px-3.5 py-2.5 text-xs font-sans ${
          isUser
            ? "bg-[var(--pane-deep)] border border-[var(--line)]"
            : "bg-[var(--card2)] border border-[var(--line)]"
        }`}
      >
        <div className="[&_p]:my-1 [&_li]:my-0.5 [&_h3]:text-[13px] [&_h4]:text-[12px]">{rendered(text)}</div>
        {!isUser && source && (
          <div className="mt-1.5 pt-1.5 border-t border-[var(--line-soft)] font-mono text-[9px] uppercase text-[var(--ink-faint)] flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--pass)" }}></span>
            {source === "local_lm" ? "CompilerAI · Local LM · grounded in audit data" : source === "llm" ? "CompilerAI · Cloud LLM · grounded in audit data" : "CompilerAI · Deterministic analyst · grounded in audit data"}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ChatBot() {
  const [open, setOpen] = useState(false);
  const [devices, setDevices] = useState([]);
  const [deviceId, setDeviceId] = useState("");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState(null);
  const scrollRef = useRef(null);
  const busyRef = useRef(false);
  busyRef.current = busy;

  useEffect(() => {
    if (!open || devices.length) return;
    api("/dashboard")
      .then((d) => {
        const audited = (d?.devices || []).filter((x) => x.audited);
        setDevices(audited);
        if (audited.length) setDeviceId((prev) => prev || audited[0].device_id);
      })
      .catch(() => {});
    api("/chat/status").then(setMode).catch(() => {});
  }, [open, devices.length]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  const send = async (question) => {
    if (!question.trim() || busyRef.current) return;
    setMessages((m) => [...m, { role: "user", text: question }]);
    setInput("");
    setBusy(true);
    try {
      const res = await api("/chat", {
        method: "POST",
        body: { question, device_id: deviceId || null },
      });
      setMessages((m) => [...m, { role: "ai", text: res.answer, source: res.source }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "ai", text: `**Chat error:** ${e.message}`, source: "template" }]);
    } finally {
      setBusy(false);
    }
  };

  // Auto-open + greet right after an audit completes anywhere in the app.
  // DeviceDetail dispatches window event "cf:audited" with the audit result.
  useEffect(() => {
    const onAudited = async (e) => {
      const { deviceId: auditedDevice, summary } = e.detail || {};
      setOpen(true);
      setMessages([]);
      if (auditedDevice) setDeviceId(auditedDevice);
      // refresh device list so the selector shows the freshly audited device
      try {
        const d = await api("/dashboard");
        const audited = (d?.devices || []).filter((x) => x.audited);
        setDevices(audited);
        if (auditedDevice) setDeviceId(auditedDevice);
      } catch {}
      const pct = summary?.compliance_pct ?? 0;
      const pass = summary?.pass_count ?? 0;
      const fail = summary?.fail_count ?? 0;
      setMessages([
        {
          role: "ai",
          text:
            `**Audit complete.** Compliance index: **${pct}%** — ${pass} passed, ${fail} failed.\n\n` +
            `Ask CompilerAI anything about this audit report — what failed, why it failed, or how to fix every issue so the next audit passes. Try the quick prompts below.`,
          source: "template",
        },
      ]);
    };
    window.addEventListener("cf:audited", onAudited);
    return () => window.removeEventListener("cf:audited", onAudited);
  }, []);

  const label =
    mode?.analyst_mode === "local_lm"
      ? "CompilerAI · Local LM"
      : mode?.analyst_mode === "llm"
      ? "CompilerAI · Cloud LLM"
      : "CompilerAI · Offline Analyst";

  return (
    <>
      {/* Launcher */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-14 right-5 z-40 btn-primary !rounded-full !px-4 !py-3 shadow-lg animate-bounce-in hover:animate-none"
          title="Audit Report Assistant"
        >
          <span className="material-symbols-outlined text-[20px]">forum</span>
          <span className="hidden sm:inline">Ask CompilerAI</span>
        </button>
      )}

      {/* Panel */}
      {open && (
        <div className="fixed bottom-14 right-5 z-50 w-[min(440px,calc(100vw-2.5rem))] h-[min(600px,calc(100vh-8rem))] card flex flex-col overflow-hidden shadow-2xl !translate-y-0 chat-panel-in">
          {/* header */}
          <div className="flex items-center justify-between gap-2 px-4 py-3 bg-[var(--chrome)] text-[var(--chrome-text)] border-b border-[var(--line)]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-md bg-[var(--accent)] flex items-center justify-center text-[#FCF9F0]">
                <span className="material-symbols-outlined text-[18px]">smart_toy</span>
              </div>
              <div>
                <div className="font-display text-sm font-bold">CompilerAI Analyst</div>
                <div className="font-mono text-[9px] uppercase tracking-wider opacity-70 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--pass)] animate-pulse"></span>
                  {label} · grounded in audit data
                </div>
              </div>
            </div>
            <button onClick={() => setOpen(false)} className="opacity-70 hover:opacity-100 transition">
              <span className="material-symbols-outlined text-[20px]">close</span>
            </button>
          </div>

          {/* device selector */}
          <div className="flex items-center gap-2 px-3 py-2 bg-[var(--pane)] border-b border-[var(--line)]">
            <span className="label-xs !text-[9px] shrink-0">Device</span>
            <select
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              className="input-field !py-1 !text-xs font-mono"
            >
              {devices.length === 0 && <option value="">No audited devices</option>}
              {devices.map((d) => (
                <option key={d.device_id} value={d.device_id}>
                  {d.hostname || d.device_id} — {d.compliance_pct}%
                </option>
              ))}
            </select>
          </div>

          {/* messages */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto px-3.5 py-3 space-y-3 bg-[var(--paper)]">
            {messages.length === 0 && (
              <div className="text-center py-4">
                <div className="w-12 h-12 mx-auto rounded-full bg-[var(--pane)] border border-[var(--line)] flex items-center justify-center text-[var(--accent)] mb-3">
                  <span className="material-symbols-outlined text-[26px]">psychology</span>
                </div>
                <p className="text-xs text-[var(--ink-soft)] leading-relaxed">
                   Ask CompilerAI anything about this device&apos;s audit report — what failed, why, and how to fix it.
                </p>
                {devices.length === 0 && (
                  <p className="mt-2 text-[10px] font-mono text-[var(--warn)]">
                    No audited devices yet —{" "}
                    <Link to="/console/upload" className="underline" onClick={() => setOpen(false)}>
                      ingest a config
                    </Link>{" "}
                    and run an audit.
                  </p>
                )}
              </div>
            )}
            {messages.map((m, i) => (
              <Bubble key={i} {...m} />
            ))}
            {busy && (
              <div className="flex gap-2.5">
                <div className="w-7 h-7 shrink-0 rounded-md bg-[var(--pass)] flex items-center justify-center text-[#FCF9F0] font-bold font-mono text-[11px]">AI</div>
                <div className="rounded-lg px-3.5 py-2.5 bg-[var(--card2)] border border-[var(--line)]">
                  <span className="flex gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--ink-faint)] animate-bounce" style={{ animationDelay: "0ms" }}></span>
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--ink-faint)] animate-bounce" style={{ animationDelay: "150ms" }}></span>
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--ink-faint)] animate-bounce" style={{ animationDelay: "300ms" }}></span>
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* quick prompts */}
          <div className="flex gap-1.5 px-3 py-2 bg-[var(--pane)] border-t border-[var(--line)] overflow-x-auto">
            {QUICK_PROMPTS.map((p) => (
              <button
                key={p.label}
                onClick={() => send(p.question)}
                disabled={busy || !devices.length}
                className="shrink-0 px-2.5 py-1 rounded-full border border-[var(--line)] bg-[var(--card)] font-mono text-[10px] text-[var(--ink-soft)] hover:text-[var(--accent)] hover:border-[var(--accent)] transition disabled:opacity-40"
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* input */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              send(input);
            }}
            className="flex items-center gap-2 p-2.5 bg-[var(--card)] border-t border-[var(--line)]"
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask CompilerAI about the audit report…"
              className="input-field !text-xs"
              disabled={busy}
            />
            <button type="submit" disabled={busy || !input.trim()} className="btn-primary !py-2 !px-3 shrink-0">
              <span className="material-symbols-outlined text-[18px]">send</span>
            </button>
          </form>
        </div>
      )}
    </>
  );
}
