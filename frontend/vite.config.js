import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// All API calls use the relative /api prefix everywhere:
// - dev: the proxy below forwards /api/* to the local backend, stripping the prefix
// - Vercel: same-origin /api rewrites route to the backend service
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
});
