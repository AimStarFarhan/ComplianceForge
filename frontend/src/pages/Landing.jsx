import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ThemeToggle } from "../components/ThemeToggle";
import Logo from "../components/Logo";

/* ---------------------------------- data ---------------------------------- */

const VENDORS = ["Cisco IOS", "Juniper SRX", "SONiC NOS"];

const PILLARS = [
  {
    icon: "shuffle",
    title: "Vendor-Agnostic Normalization",
    body: "Every config — Cisco, Juniper, SONiC — compiles into the same Security Baseline Model: auth, logging, access control, crypto, services. Rules are written once, against the baseline, not against vendor dialects.",
  },
  {
    icon: "shield_lock",
    title: "Sandboxed Rule Engine",
    body: "15+ CIS-style checks run through an evaluator we wrote ourselves — a whitelisted AST walker, never a raw eval. We tried to break it with injected rule packs. It held.",
  },
  {
    icon: "psychology",
    title: "Zero-Code Learning Loop",
    body: "Hit an unknown vendor's syntax? Lines are classified with AI-proposed categories and queued for one human click — not a new parser, not a redeploy, not an engineering ticket.",
  },
  {
    icon: "verified_user",
    title: "Human-Verified, Always",
    body: "AI proposes a category. It never decides pass or fail. Every learned mapping traces back to a named admin who confirmed it — the audit trail says so, line by line.",
  },
];

const TOURS = [
  {
    role: "Network / Security Engineer",
    icon: "terminal",
    headline: "A scored audit with exact CLI fixes in under a minute",
    points: [
      "Upload the raw config — vendor is auto-detected",
      "Severity-ranked findings with the offending line quoted",
      "Copy-paste remediation CLI for every finding",
    ],
    to: "/console/upload",
    cta: "Run a live audit",
  },
  {
    role: "Compliance Auditor",
    icon: "plagiarism",
    headline: "An audit-ready PDF mapped to CIS controls",
    points: [
      "Per-device report: score, findings, remediation runbook",
      "Every rule cites its control-family mapping",
      "Learned findings are tagged ai_suggested_human_confirmed",
    ],
    to: "/console/reports",
    cta: "View reports",
  },
  {
    role: "Training Loop Admin",
    icon: "model_training",
    headline: "Confirm a pattern once — the vendor is known forever",
    points: [
      "Unknown lines arrive with an AI-proposed category",
      "Confirm one-by-one, or bulk-train the whole file",
      "Numbers and IPs are templated out — similar lines auto-match",
    ],
    to: "/console/training",
    cta: "Open the queue",
  },
];

const STATS = [
  { n: "15+", label: "CIS-style rules enforced" },
  { n: "3", label: "vendor syntaxes, day one" },
  { n: "0", label: "lines of parser code to learn a vendor" },
  { n: "100%", label: "of findings human-confirmed" },
];

const HONEST_REAL = [
  "Three hand-verified parsers: Cisco IOS, Juniper SRX, SONiC",
  "15+ rules per vendor against a vendor-neutral baseline",
  "Safe AST rule evaluator — injection attempts return status=error",
  "Per-device PDF reports with full remediation CLI",
  "The live learn-a-new-vendor loop, demonstrated on unseen fixtures",
  "Offline deterministic fallback — demos don't break without an API key",
];

const HONEST_NOT = [
  {
    title: "No auto-remediation",
    body: "Findings and fix commands are advisory. Nothing is pushed to a device. A wrong generated command on live fleet hardware is worse than a manual fix.",
  },
  {
    title: "No live SSH polling",
    body: "v1 ingests static config files. Pulling live from devices means credentials, rotation, and blast radius we deliberately did not take on for this build.",
  },
  {
    title: "No unattended operation",
    body: "The AI layer never issues verdicts. If the LLM is wrong, a human corrects it before it becomes a rule. That gate is the product, not a limitation we hide.",
  },
];

const COMPARE = [
  { name: "ComplianceForge", us: true, learns: true, cis: true, pdf: true, adaptive: true },
  { name: "Tufin", us: false, learns: false, cis: true, pdf: true, adaptive: false },
  { name: "FireMon", us: false, learns: false, cis: true, pdf: true, adaptive: false },
  { name: "Titania Nipper", us: false, learns: false, cis: true, pdf: true, adaptive: false },
  { name: "SolarWinds NCM", us: false, learns: false, cis: true, pdf: true, adaptive: false },
];

/* -------------------------------- animation -------------------------------- */

function useInView(threshold = 0.2) {
  const ref = useRef(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          setSeen(true);
          io.disconnect();
        }
      },
      { threshold }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [threshold]);
  return [ref, seen];
}

function Reveal({ children, className = "", delay = 0 }) {
  const [ref, seen] = useInView();
  return (
    <div
      ref={ref}
      className={className}
      style={{
        opacity: seen ? 1 : 0,
        transform: seen ? "translateY(0)" : "translateY(18px)",
        transition: `opacity .7s cubic-bezier(.22,1,.36,1) ${delay}ms, transform .7s cubic-bezier(.22,1,.36,1) ${delay}ms`,
      }}
    >
      {children}
    </div>
  );
}

function Counter({ value, className = "" }) {
  const [ref, seen] = useInView();
  const isNum = /^\d/.test(value);
  const target = isNum ? parseInt(value) : null;
  const [n, setN] = useState(isNum ? 0 : null);
  useEffect(() => {
    if (!seen || target === null) return;
    if (typeof requestAnimationFrame !== "function") {
      setN(target);
      return;
    }
    let raf;
    let done = false;
    const t0 = performance.now();
    const dur = 900;
    const tick = (t) => {
      const p = Math.min((t - t0) / dur, 1);
      setN(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
      else done = true;
    };
    raf = requestAnimationFrame(tick);
    // Safety net: if rAF never fires (headless capture, background tab),
    // snap to the final value after 1.5s so the real number is never lost.
    const fallback = setTimeout(() => {
      if (!done) setN(target);
    }, 1500);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(fallback);
    };
  }, [seen, target]);
  if (!isNum) return <span className={className}>{value}</span>;
  return (
    <span ref={ref} className={className}>
      {n ?? 0}
      {value.replace(/^[\d,]+/, "")}
    </span>
  );
}

/* ------------------------------ hero pipeline ------------------------------ */

const HERO_STAGES = [
  { tag: "INGEST", lines: ["hostname EDGE-RT-07", "line vty 0 4", " transport input all", "snmp-server community public RO"] },
  { tag: "NORMALIZE", lines: ["auth.vty_lines = 5", "auth.cleartext_transport = true", "snmp.community_default = true", "→ Security Baseline Model"] },
  { tag: "AUDIT", lines: ["VTY-02  cleartext VTY access   FAIL", "SNMP-01 default community    FAIL", "AUTH-01 default credentials   FAIL", "LOG-05  buffered logging      PASS"] },
  { tag: "TRAIN", lines: ["security-zone TRUST-EDGE", "→ AI proposal: zone (87%)", "→ admin: confirmed", "→ pattern cached — vendor known"] },
];

function HeroPipeline() {
  const [stage, setStage] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setStage((s) => (s + 1) % 4), 2600);
    return () => clearInterval(t);
  }, []);
  const s = HERO_STAGES[stage];
  return (
    <div className="relative border border-cfline rounded-xl bg-cfsurface/80 backdrop-blur-sm overflow-hidden">
      {/* header */}
      <div className="flex items-center justify-between px-4 h-10 border-b border-cfline">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cfdim" />
          <span className="w-2 h-2 rounded-full bg-cfdim" />
          <span className="w-2 h-2 rounded-full bg-cfdim" />
        </div>
        <span className="font-mono text-[10px] text-cfmuted tracking-[0.08em] uppercase">
          pipeline · {s.tag.toLowerCase()}
        </span>
        <span className="font-mono text-[10px] text-cfsignal animate-pulseSoft tracking-[0.08em]">● LIVE</span>
      </div>
      {/* stage stepper */}
      <div className="grid grid-cols-4 gap-px bg-cfline border-b border-cfline">
        {HERO_STAGES.map((h, i) => (
          <div
            key={h.tag}
            className={`px-3 py-2 font-mono text-[9px] tracking-[0.1em] transition-colors duration-300 ${
              i === stage ? "bg-cfsignal/10 text-cfsignal" : i < stage ? "text-cfmuted" : "text-cfdim"
            }`}
          >
            {String(i + 1).padStart(2, "0")} {h.tag}
            {i === stage && <span className="ml-1.5 inline-block w-1 h-1 bg-cfsignal rounded-full animate-pulseSoft" />}
          </div>
        ))}
      </div>
      {/* code body */}
      <div className="relative min-h-[196px] p-4 font-mono text-[12px] leading-[1.9]">
        {s.lines.map((l, i) => (
          <div
            key={l}
            className="whitespace-pre"
            style={{ animation: `fadeUp .5s ease ${i * 130}ms both` }}
          >
            {l.includes("FAIL") ? (
              <span className="text-cffail">{l}</span>
            ) : l.includes("PASS") ? (
              <span className="text-cfpass">{l}</span>
            ) : l.startsWith("→") ? (
              <span className="text-cfsignal">{l}</span>
            ) : (
              <span className="text-cftext/80">{l}</span>
            )}
          </div>
        ))}
        {/* scanline sweep */}
        <div
          className="absolute left-0 right-0 h-10 pointer-events-none"
          style={{
            background: "linear-gradient(180deg, transparent, color-mix(in srgb, var(--accent) 10%, transparent), transparent)",
            animation: "scanline 2.8s ease-in-out infinite",
          }}
        />
      </div>
      {/* footer strip */}
      <div className="flex items-center justify-between px-4 h-9 border-t border-cfline font-mono text-[10px] text-cfmuted">
        <span>4 passes · one engine</span>
        <span>
          <span className="text-cfpass">●</span> 0 new parsers written
        </span>
      </div>
    </div>
  );
}

/* ------------------------------ small components ---------------------------- */

function Mark({ inverse }) {
  return (
    <div className="flex items-center gap-2.5">
      <Logo className={`h-7 w-7 rounded-[6px] ${inverse ? "ring-1 ring-cfline" : ""}`} />
      <span className="font-display text-[16px] font-semibold tracking-tight">ComplianceForge</span>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div className="font-mono text-[10px] tracking-[0.14em] uppercase text-cfsignal mb-3">{children}</div>
  );
}

/* ---------------------------------- page ---------------------------------- */

export default function Landing() {
  return (
    <div className="min-h-screen bg-cfink text-cftext font-sans">
      {/* ---------------- nav ---------------- */}
      <header className="fixed top-0 inset-x-0 z-50 border-b border-cfline bg-cfink/80 backdrop-blur-md">
        <div className="max-w-6xl mx-auto h-14 px-6 flex items-center justify-between">
          <Mark />
          <nav className="hidden md:flex items-center gap-7 font-mono text-[11px] text-cfmuted">
            <a href="#engine" className="m-link hover:text-cftext transition-colors">Engine</a>
            <a href="#tours" className="m-link hover:text-cftext transition-colors">Your Role</a>
            <a href="#honest" className="m-link hover:text-cftext transition-colors">Honesty</a>
            <a href="#compare" className="m-link hover:text-cftext transition-colors">Compare</a>
          </nav>
          <ThemeToggle />
          <Link
            to="/console"
            className="font-mono text-[11px] font-semibold px-3.5 py-1.5 rounded-md bg-cfsignal text-[#FCF9F0] hover:bg-cfsignalDeep transition-colors"
          >
            OPEN CONSOLE →
          </Link>
        </div>
      </header>

      {/* ---------------- hero ---------------- */}
      <section className="relative pt-14 border-b border-cfline overflow-hidden">
        {/* glow orb (landing-preview floaty) */}
        <div className="m-orb" />
        <div className="max-w-6xl mx-auto px-6 pt-20 pb-16 relative">
          <div className="grid md:grid-cols-2 gap-14 items-center">
            <div>
              <Reveal>
                <div className="inline-flex items-center gap-2.5 border border-cfline rounded-full px-3.5 py-1.5 mb-7">
                  <span className="w-1.5 h-1.5 rounded-full bg-cfsignal animate-pulseSoft" />
                  <span className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfmuted">
                    AI-Augmented · Vendor-Agnostic · Human-in-the-Loop
                  </span>
                </div>
              </Reveal>
              <Reveal delay={80}>
                <h1 className="font-display text-[46px] md:text-[60px] leading-[1.04] font-semibold tracking-[-0.015em] mb-6">
                  One Engine.
                  <br />
                  Every Vendor.
                  <br />
                  <span className="m-shimmer italic">Zero New Code.</span>
                </h1>
              </Reveal>
              <Reveal delay={160}>
                <p className="text-[14px] leading-relaxed text-cfmuted max-w-[480px] mb-9">
                  ComplianceForge parses, audits, and remediates multi-vendor network configs —
                  and when it meets a vendor it has never seen, it teaches itself the syntax,
                  with a human confirming every step.
                </p>
              </Reveal>
              <Reveal delay={240}>
                <div className="flex flex-wrap gap-3">
                  <Link
                    to="/console/upload"
                    className="font-mono text-[12px] font-semibold px-5 py-3 rounded-md bg-cfsignal text-[#FCF9F0] hover:bg-cfsignalDeep transition-colors"
                  >
                    SEE A LIVE AUDIT →
                  </Link>
                  <a
                    href="#loop"
                    className="font-mono text-[12px] font-semibold px-5 py-3 rounded-md border border-cfline text-cfmuted hover:text-cftext hover:border-cfmuted transition-colors"
                  >
                    WATCH THE TRAINING LOOP
                  </a>
                </div>
              </Reveal>
            </div>
            <Reveal delay={200}>
              <HeroPipeline />
            </Reveal>
          </div>
        </div>
      </section>

      {/* ---------------- vendors strip (marquee) ---------------- */}
      <section className="border-b border-cfline overflow-hidden">
        <div className="py-8">
          <div className="font-mono text-[10px] tracking-[0.12em] uppercase text-cfdim mb-5 text-center">
            Tested against real-world config patterns from
          </div>
          <div className="m-marquee">
            <div className="m-marquee-track font-mono text-[14px] font-semibold">
              {[0, 1].map((dup) => (
                <span key={dup} className="flex gap-12 shrink-0">
                  {VENDORS.map((v) => (
                    <span key={v} className="text-cfmuted hover:text-cftext transition-colors">{v}</span>
                  ))}
                  <span className="text-cfmuted">Enterprise fleets</span>
                  <span className="text-cfmuted">Human-in-the-loop</span>
                  <span className="text-cfmuted">CIS-style rules</span>
                  <span className="text-cfsignal italic">+ your next learned vendor</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- engine / 4 pillars ---------------- */}
      <section id="engine" className="border-b border-cfline">
        <div className="max-w-6xl mx-auto px-6 py-20">
          <Reveal>
            <SectionLabel>The engine</SectionLabel>
            <h2 className="font-display text-3xl md:text-4xl font-semibold tracking-[-0.01em] mb-4 max-w-xl">
              One compiler. Four passes.
            </h2>
            <p className="text-[14px] text-cfmuted max-w-xl mb-12 leading-relaxed">
              Everything a device config is — every interface, ACL, VTY line, crypto setting —
              gets compiled into one vendor-neutral baseline the rule engine can reason about.
            </p>
          </Reveal>
          <div className="grid sm:grid-cols-2 gap-4">
            {PILLARS.map((p, i) => (
              <Reveal key={p.title} delay={i * 90}>
                <div className="group/card h-full border border-cfline rounded-xl p-6 bg-cfsurface/40 hover:bg-cfsurface hover:border-cfsignal/30 transition-all duration-300">
                  <div className="m-ic w-10 h-10 rounded-lg border border-cfline flex items-center justify-center mb-5 text-cfsignal">
                    <span className="material-symbols-outlined text-[20px]">{p.icon}</span>
                  </div>
                  <div className="text-[15px] font-semibold mb-2.5">{p.title}</div>
                  <div className="text-[12.5px] leading-relaxed text-cfmuted">{p.body}</div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---------------- role tours ---------------- */}
      <section id="tours" className="border-b border-cfline bg-cfink2">
        <div className="max-w-6xl mx-auto px-6 py-20">
          <Reveal>
            <SectionLabel>Your role</SectionLabel>
            <h2 className="font-display text-3xl md:text-4xl font-semibold tracking-[-0.01em] mb-4">
              See how it works for you
            </h2>
          </Reveal>
          <div className="grid md:grid-cols-3 gap-4 mt-12">
            {TOURS.map((t, i) => (
              <Reveal key={t.role} delay={i * 100}>
                <div className="h-full border border-cfline rounded-xl bg-cfsurface/40 p-6 flex flex-col hover:border-cfsignal/30 transition-colors">
                  <div className="flex items-center gap-3 mb-4">
                    <span className="material-symbols-outlined text-[20px] text-cfsignal">{t.icon}</span>
                    <span className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfmuted">{t.role}</span>
                  </div>
                  <div className="text-[15px] font-semibold leading-snug mb-4">{t.headline}</div>
                  <ul className="space-y-2 mb-6 flex-1">
                    {t.points.map((pt) => (
                      <li key={pt} className="flex gap-2.5 text-[12px] text-cfmuted leading-relaxed">
                        <span className="text-cfsignal">→</span>
                        <span>{pt}</span>
                      </li>
                    ))}
                  </ul>
                  <Link
                    to={t.to}
                    className="font-mono text-[11px] font-semibold text-cfsignal hover:text-cfsignal transition-colors"
                  >
                    {t.cta.toUpperCase()} →
                  </Link>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---------------- training loop flagship ---------------- */}
      <section id="loop" className="border-b border-cfline">
        <div className="max-w-6xl mx-auto px-6 py-20 grid lg:grid-cols-2 gap-14 items-center">
          <Reveal>
            <SectionLabel>The flagship</SectionLabel>
            <h2 className="font-display text-3xl md:text-4xl font-semibold tracking-[-0.01em] mb-5 leading-tight">
              A compiler that learns a language it's never seen
            </h2>
            <p className="text-[14px] text-cfmuted leading-relaxed mb-6">
              Every commercial auditor — Tufin, FireMon, Nipper, SolarWinds — audits only the
              vendors it was engineered for. ComplianceForge converts an unknown device into a
              known one, live, in front of the auditor.
            </p>
            <ol className="space-y-3.5 mb-8">
              {[
                "Ingest a config from a vendor nobody has seen — every unrecognized line lands in the Training Queue with an AI-proposed category",
                "A human admin confirms or corrects — one line at a time, or one click to train on the whole file",
                "Confirmed mappings are stored as normalized patterns — numbers and IPs templated out",
                "Re-ingest the same vendor: every line auto-recognizes, full rule audits run, findings tagged ai_suggested_human_confirmed",
              ].map((s, i) => (
                <li key={i} className="group flex gap-4 text-[13px] text-cftext/90 leading-relaxed transition-transform duration-300 hover:translate-x-1">
                  <span className="font-mono text-[11px] text-cfsignal shrink-0 mt-0.5">{String(i + 1).padStart(2, "0")}</span>
                  <span>{s}</span>
                </li>
              ))}
            </ol>
            <Link
              to="/console/training"
              className="font-mono text-[12px] font-semibold px-5 py-3 rounded-md bg-cfsignal text-[#FCF9F0] hover:bg-cfsignalDeep transition-colors inline-block"
            >
              TRY THE TRAINING LOOP →
            </Link>
          </Reveal>
          <Reveal delay={150}>
            <div className="border border-cfline rounded-xl bg-cfsurface/60 overflow-hidden">
              <div className="px-4 py-3 border-b border-cfline flex items-center justify-between">
                <span className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfmuted">
                  Training Queue · unseen vendor
                </span>
                <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-cfpass/10 text-cfpass border border-cfpass/25">
                  AI PROPOSES · HUMAN DECIDES
                </span>
              </div>
              <div className="divide-y divide-cfline/60">
                {[
                  { line: "security-zone TRUST-EDGE", guess: "zone", conf: "87%", by: "admin_sec9" },
                  { line: "setpolicy fw-pass 10 permit", guess: "acl_rule", conf: "92%", by: "admin_sec9" },
                  { line: "cryptomap level aes-256-gcm", guess: "encryption", conf: "78%", by: "admin_sec9" },
                ].map((r) => (
                  <div key={r.line} className="px-4 py-3.5 flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      <div className="font-mono text-[12px] truncate">{r.line}</div>
                      <div className="font-mono text-[10px] text-cfdim mt-1">
                        AI: <span className="text-cfsignal">{r.guess}</span> · confidence {r.conf} · confirmed by <span className="text-cfmuted">{r.by}</span>
                      </div>
                    </div>
                    <span className="font-mono text-[9px] font-bold tracking-[0.08em] px-2 py-1 rounded bg-cfpass/10 text-cfpass border border-cfpass/25 shrink-0">
                      ✓ CONFIRMED
                    </span>
                  </div>
                ))}
              </div>
              <div className="px-4 py-3 border-t border-cfline font-mono text-[10px] text-cfdim">
                pattern cache: 3 stored · next config from this vendor auto-recognizes
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---------------- stats ---------------- */}
      <section className="border-b border-cfline bg-cfink2">
        <div className="max-w-6xl mx-auto px-6 py-16">
          <Reveal>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-cfline border border-cfline rounded-xl overflow-hidden">
              {STATS.map((s) => (
                <div key={s.label} className="bg-cfink2 p-8 text-center">
                  <div className="font-mono text-[34px] font-bold text-cfsignal mb-1.5">
                    <Counter value={s.n} />
                  </div>
                  <div className="font-mono text-[10px] tracking-[0.08em] uppercase text-cfmuted leading-relaxed px-2">
                    {s.label}
                  </div>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---------------- honesty section ---------------- */}
      <section id="honest" className="border-b border-cfline">
        <div className="max-w-6xl mx-auto px-6 py-20">
          <Reveal>
            <SectionLabel>Feasibility & what we're honest about</SectionLabel>
            <h2 className="font-display text-3xl md:text-4xl font-semibold tracking-[-0.01em] mb-4 max-w-lg">
              Trust through transparency, not logos
            </h2>
          </Reveal>
          <div className="grid lg:grid-cols-3 gap-4 mt-12">
            <Reveal>
              <div className="h-full border border-cfline rounded-xl p-6 bg-cfsurface/40">
                <div className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfpass mb-5">
                  ● Working today
                </div>
                <ul className="space-y-3">
                  {HONEST_REAL.map((r) => (
                    <li key={r} className="flex gap-2.5 text-[12px] leading-relaxed">
                      <span className="text-cfpass shrink-0">✓</span>
                      <span className="text-cfmuted">{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Reveal>
            {HONEST_NOT.map((n, i) => (
              <Reveal key={n.title} delay={(i + 1) * 90}>
                <div className="h-full border border-cfline rounded-xl p-6 bg-cfsurface/40">
                  <div className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfwarn mb-4">
                    ○ Not built, on purpose
                  </div>
                  <div className="text-[14px] font-semibold mb-2.5">{n.title}</div>
                  <div className="text-[12px] text-cfmuted leading-relaxed">{n.body}</div>
                </div>
              </Reveal>
            ))}
          </div>
          <Reveal delay={200}>
            <div className="mt-4 border border-cfline rounded-xl p-6 bg-cfsurface/40">
              <div className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfsignal mb-3">
                → What's next
              </div>
              <div className="text-[12px] text-cfmuted leading-relaxed max-w-2xl">
                Real hardware testing. The parsers are verified against synthetic fixtures built
                from public vendor CLI references; the next milestone is the same audits against
                physical lab devices and their true dialects.
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---------------- comparison ---------------- */}
      <section id="compare" className="border-b border-cfline bg-cfink2">
        <div className="max-w-6xl mx-auto px-6 py-20">
          <Reveal>
            <SectionLabel>The one thing incumbents can't</SectionLabel>
            <h2 className="font-display text-3xl md:text-4xl font-semibold tracking-[-0.01em] mb-4 max-w-xl">
              Every tool audits known vendors. Only one learns new ones.
            </h2>
          </Reveal>
          <Reveal delay={100}>
            <div className="mt-10 border border-cfline rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full font-mono text-[11.5px]">
                  <thead>
                    <tr className="border-b border-cfline text-cfdim">
                      <th className="text-left px-5 py-3.5 font-medium tracking-[0.06em] uppercase text-[10px]">Tool</th>
                      <th className="text-left px-5 py-3.5 font-medium tracking-[0.06em] uppercase text-[10px]">
                        Learns an unseen vendor without new code
                      </th>
                      <th className="text-left px-5 py-3.5 font-medium tracking-[0.06em] uppercase text-[10px]">CIS-style rules</th>
                      <th className="text-left px-5 py-3.5 font-medium tracking-[0.06em] uppercase text-[10px]">PDF reports</th>
                      <th className="text-left px-5 py-3.5 font-medium tracking-[0.06em] uppercase text-[10px]">Human-confirmed AI</th>
                    </tr>
                  </thead>
                  <tbody>
                    {COMPARE.map((r) => (
                      <tr
                        key={r.name}
                        className={`border-b border-cfline/50 last:border-0 ${
                          r.us ? "bg-cfsignal/[0.06]" : ""
                        }`}
                      >
                        <td className={`px-5 py-3.5 ${r.us ? "text-cfsignal font-bold" : "text-cftext"}`}>
                          {r.us && <span className="mr-1.5">▸</span>}
                          {r.name}
                        </td>
                        <td className="px-5 py-3.5">
                          {r.learns ? (
                            <span className="text-cfpass font-bold">✓ YES</span>
                          ) : (
                            <span className="text-cffail">✕ NO</span>
                          )}
                        </td>
                        <td className="px-5 py-3.5 text-cfmuted">{r.cis ? "✓" : "—"}</td>
                        <td className="px-5 py-3.5 text-cfmuted">{r.pdf ? "✓" : "—"}</td>
                        <td className="px-5 py-3.5 text-cfmuted">{r.adaptive ? "✓" : "✕"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---------------- close CTA ---------------- */}
      <section className="relative border-b border-cfline overflow-hidden">
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ background: "radial-gradient(500px 200px at 50% 100%, color-mix(in srgb, var(--accent) 8%, transparent), transparent 70%)" }}
        />
        <div className="max-w-6xl mx-auto px-6 py-24 text-center relative">
          <Reveal>
            <h2 className="font-display text-3xl md:text-4xl font-semibold tracking-[-0.01em] mb-4">
              Compile your first config
            </h2>
            <p className="text-[13px] text-cfmuted mb-8 max-w-md mx-auto leading-relaxed">
              Grab a fixture from the repo — or bring a config from a vendor we've never met.
              That's the interesting one.
            </p>
            <div className="flex flex-wrap gap-3 justify-center">
              <Link
                to="/console/upload"
                className="font-mono text-[12px] font-semibold px-6 py-3.5 rounded-md bg-cfsignal text-[#FCF9F0] hover:bg-cfsignalDeep transition-colors"
              >
                TRY THE LIVE AUDIT →
              </Link>
              <Link
                to="/console"
                className="font-mono text-[12px] font-semibold px-6 py-3.5 rounded-md border border-cfline text-cfmuted hover:text-cftext hover:border-cfmuted transition-colors"
              >
                OPEN THE CONSOLE
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---------------- footer ---------------- */}
      <footer className="bg-cfink">
        <div className="max-w-6xl mx-auto px-6 py-14">
          <div className="flex flex-col md:flex-row justify-between gap-10">
            <div className="max-w-xs">
              <Mark inverse />
              <p className="font-mono text-[11px] text-cfdim leading-relaxed mt-4">
                AI-augmented, vendor-agnostic network security compliance auditor.
                Advisory-only remediation. Human-confirmed learning.
              </p>
            </div>
            <div className="flex gap-16">
              <div>
                <div className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfmuted mb-4">Product</div>
                <ul className="space-y-2.5 font-mono text-[11px] text-cfdim">
                  <li><a href="#engine" className="hover:text-cftext transition-colors">The Engine</a></li>
                  <li><a href="#loop" className="hover:text-cftext transition-colors">Training Loop</a></li>
                  <li><a href="#compare" className="hover:text-cftext transition-colors">Comparison</a></li>
                  <li><Link to="/console/upload" className="hover:text-cftext transition-colors">Live Audit</Link></li>
                </ul>
              </div>
              <div>
                <div className="font-mono text-[10px] tracking-[0.1em] uppercase text-cfmuted mb-4">Console</div>
                <ul className="space-y-2.5 font-mono text-[11px] text-cfdim">
                  <li><Link to="/console" className="hover:text-cftext transition-colors">Dashboard</Link></li>
                  <li><Link to="/console/training" className="hover:text-cftext transition-colors">Training Queue</Link></li>
                  <li><Link to="/console/devices" className="hover:text-cftext transition-colors">Devices</Link></li>
                  <li><Link to="/console/reports" className="hover:text-cftext transition-colors">Reports</Link></li>
                </ul>
              </div>
            </div>
          </div>
          <div className="mt-12 pt-6 border-t border-cfline flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-[10px] text-cfdim">
            <span>© 2026 ComplianceForge</span>
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-cfpass animate-pulseSoft" />
              All engine systems operational
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
