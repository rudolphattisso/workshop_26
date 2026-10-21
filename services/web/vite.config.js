import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En développement (npm run dev), /api est relayé vers la passerelle locale (compose.dev.yml, profil app) :
// le navigateur parle à une seule origine, comme derrière le WAF en production.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:8080" } },
});
