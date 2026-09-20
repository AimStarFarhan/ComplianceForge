import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, setToken, API } from "../lib/api";
import Logo from "../components/Logo";

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const data = await api("/login", { method: "POST", body: { username, password } });
      setToken(data.token);
      navigate("/console");
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-tacticalOlive">
      <form onSubmit={submit} className="bg-warm-sandstone border border-weatheredTaupe rounded-lg p-8 w-96 space-y-4 shadow-md">
        <div>
          <Link to="/" className="flex items-center gap-2.5 group" title="Back to landing page">
            <Logo className="h-9 w-9 rounded-lg" />
            <span className="font-display text-2xl font-semibold text-peatCharcoal group-hover:text-sprucePine transition-colors">ComplianceForge</span>
          </Link>
          <div className="font-mono text-[10px] uppercase tracking-wider text-taupe-muted mt-1">Unified network control plane</div>
        </div>
        <div className="space-y-3">
          <div>
            <label className="label-md block mb-1">Username</label>
            <input className="input-field" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div>
            <label className="label-md block mb-1">Password</label>
            <input type="password" className="input-field" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="admin" autoFocus />
          </div>
        </div>
        {error && <div className="font-mono text-xs text-terracottaRust">{error}</div>}
        <button type="submit" className="btn-primary w-full justify-center !py-2.5">Sign in — Admin Role</button>
        <div className="font-mono text-[10px] leading-relaxed text-taupe-muted">
          Only the named admin role can approve CompilerAI-suggested mappings (the human-in-the-loop gate).
          Backend at <span className="font-mono text-sprucePine">{API}</span> — default demo credentials admin/admin.
        </div>
      </form>
    </div>
  );
}
