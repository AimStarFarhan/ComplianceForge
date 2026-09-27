import { ToastProvider } from "./components/Toast";
import { ThemeProvider } from "./components/ThemeToggle";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import { API, ensureLogin } from "./lib/api";
import ConsoleLayout from "./components/ConsoleLayout";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import ReportPreview from "./pages/ReportPreview";
import TrainingLoop from "./pages/TrainingLoop";
import UploadIngest from "./pages/UploadIngest";
import WarmupSplash from "./components/WarmupSplash";
import { JobsProvider } from "./lib/jobs";

// Cold starts (serverless backend) can take a minute: poll /health and show
// the warmup splash instead of an error until the API answers.
const MAX_ATTEMPTS = 40;
const POLL_MS = 2500;

async function healthOnce(timeoutMs = 8000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(`${API}/health`, { signal: ctl.signal });
    return r.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

// Stable component identity (defined outside App): if this were declared
// inside App, every elapsed/attempt tick would remount the whole console.
function ConsoleGate({ ready, attempt, elapsed, failed, onReady }) {
  if (ready) return <ConsoleLayout />;
  return (
    <WarmupSplash
      attempt={attempt}
      elapsed={elapsed}
      failed={failed}
      onRetry={() => window.location.reload()}
      onContinue={onReady}
    />
  );
}

export default function App() {
  const [backend, setBackend] = useState("checking"); // checking | ready
  const [attempt, setAttempt] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const stopRef = useRef(false);
  const readyRef = useRef(false);

  useEffect(() => {
    stopRef.current = false;
    const t0 = Date.now();
    const tick = setInterval(() => {
      if (!readyRef.current) setElapsed(Math.round((Date.now() - t0) / 1000));
    }, 1000);
    (async () => {
      try { await ensureLogin(); } catch {}
      for (let i = 1; i <= MAX_ATTEMPTS && !stopRef.current; i++) {
        setAttempt(i);
        if (await healthOnce()) {
          if (!stopRef.current) {
            readyRef.current = true;
            setBackend("ready");
          }
          break;
        }
        if (i < MAX_ATTEMPTS && !stopRef.current) {
          await new Promise((r) => setTimeout(r, POLL_MS));
        }
      }
    })();
    return () => { stopRef.current = true; clearInterval(tick); };
  }, []);

  const failed = backend === "checking" && attempt >= MAX_ATTEMPTS;

  // Landing renders instantly; only /console waits for the backend:
  // landing page ──▶ backend waking up ──▶ console.
  // Polling starts on mount, so the backend is usually warm by click time.

  return (
    <ThemeProvider>
      <ToastProvider>
        <BrowserRouter>
        <JobsProvider>
        <Routes>
          {/* Marketing landing page */}
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          {/* Embedded ComplianceForge console (gated on backend health) */}
          <Route
            path="/console"
            element={
              <ConsoleGate
                ready={backend === "ready"}
                attempt={attempt}
                elapsed={elapsed}
                failed={failed}
                onReady={() => {
                  readyRef.current = true;
                  setBackend("ready");
                }}
              />
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="devices" element={<Devices />} />
            <Route path="devices/:deviceId" element={<DeviceDetail />} />
            <Route path="training" element={<TrainingLoop />} />
            <Route path="upload" element={<UploadIngest />} />
            <Route path="reports" element={<ReportPreview />} />
          </Route>
          <Route path="*" element={<Landing />} />
        </Routes>
        </JobsProvider>
      </BrowserRouter>
      </ToastProvider>
    </ThemeProvider>
  );
}
