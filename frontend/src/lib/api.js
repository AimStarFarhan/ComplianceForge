import { useEffect, useState } from "react";

// Local dev: Vite proxies /api/* -> 127.0.0.1:8000 (strips the prefix).
// Production (Vercel): same-origin /api routes to the backend service.
// VITE_API_BASE overrides for any custom setup (e.g. "http://127.0.0.1:8000").
const BASE = import.meta.env.VITE_API_BASE || "/api";
export const API = BASE;

const TOKEN_KEY = "cf-token";

export function getToken() {
  return window.localStorage.getItem(TOKEN_KEY);
}
export function setToken(t) {
  window.localStorage.setItem(TOKEN_KEY, t);
}
export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function api(path, { method = "GET", body, files, isForm = false } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let payload;
  if (files) {
    payload = files; // FormData with 'file' entry — browser sets content-type
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const res = await fetch(`${API}${path}`, { method, headers, body: payload });
  if (res.status === 401) {
    clearToken();
  }
  if (!res.ok) {
    let detail = "";
    const isJson = (res.headers.get("content-type") || "").includes("json");
    if (isJson) {
      try {
        const j = await res.json();
        detail = j.detail || JSON.stringify(j);
      } catch {
        detail = res.statusText;
      }
    } else {
      detail = res.statusText;
    }
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  // PDF and other binary responses — caller handles the blob
  if ((res.headers.get("content-type") || "").includes("application/pdf")) {
    return res.blob();
  }
  return res.json();
}

/** Login once at app start; the demo has a single admin role. */
export async function ensureLogin() {
  if (getToken()) return true;
  const res = await fetch(`${API}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "admin" }),
  });
  if (!res.ok) return false;
  const data = await res.json();
  setToken(data.token);
  return true;
}

export function useApi(path, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const reload = async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api(path));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);

  return { data, error, loading, reload };
}
