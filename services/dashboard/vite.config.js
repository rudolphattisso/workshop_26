import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En développement (npm run dev) : mêmes chemins que derrière le nginx du dashboard (voir nginx.conf).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api/auth": "http://127.0.0.1:8001",
      "/api/remediation": {
        target: "http://127.0.0.1:8004",
        rewrite: (path) => path.replace(/^\/api\/remediation/, ""),
      },
    },
  },
});
