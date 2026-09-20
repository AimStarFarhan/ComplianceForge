import { useEffect, useState } from "react";
import { Navigate, Outlet } from "react-router-dom";
import Header from "./Header";
import Sidebar from "./Sidebar";
import Footer from "./Footer";
import ChatBot from "./ChatBot";
import { API, getToken } from "../lib/api";

/** The embedded ComplianceForge console — mounted under /console/* behind the landing page. */
export default function ConsoleLayout() {
  const token = getToken();
  const [demo, setDemo] = useState(null); // null = still checking

  useEffect(() => {
    if (token) return;
    fetch(`${API}/health`)
      .then((r) => (r.ok ? r.json() : null))
      .then((h) => setDemo(!!h?.demo_open))
      .catch(() => setDemo(false));
  }, [token]);

  // Public demo deployments (CF_DEMO_OPEN=1) skip the login gate entirely
  // so a shared link opens the console directly. Otherwise require a token.
  if (!token && demo !== true) {
    if (demo === null) {
      return <div className="min-h-screen flex items-center justify-center font-mono text-xs">Loading console…</div>;
    }
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="min-h-screen bg-rawPutty text-peatCharcoal">
      <Header />
      <Sidebar />
      <div className="pl-64">
        <main className="w-full min-h-screen pt-24 pb-16 px-6">
          <div className="flex flex-col w-full max-w-[1540px] mx-auto gap-5">
            <Outlet />
          </div>
        </main>
      </div>
      <Footer />
      <ChatBot />
    </div>
  );
}
