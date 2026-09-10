import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// On Vercel the FastAPI backend is mounted at /api (same origin — no CORS needed).
// Locally the dev proxy handles the same path -> 127.0.0.1:8000.
const isProd = process.env.VERCEL === "1";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
  define: {
    "import.meta.env.VITE_API_BASE": JSON.stringify(isProd ? "/api" : ""),
  },
});
