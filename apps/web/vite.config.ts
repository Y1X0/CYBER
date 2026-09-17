import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// The fetch-directive half of the production CSP, kept in sync with public/_headers. Injected into
// the BUILT index.html only (never the dev server, whose HMR needs an inline preamble that
// script-src 'self' would block). frame-ancestors is header-only, so it stays in _headers.
const CSP =
  "default-src 'self'; script-src 'self'; " +
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
  "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; " +
  "connect-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'";

// Defence in depth for a static host that ignores _headers: stamp the CSP into the built HTML as a
// <meta http-equiv>. Build-only (`apply: "build"`) so the dev server keeps working.
function cspMeta(): Plugin {
  return {
    name: "guardian-csp-meta",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        "</title>",
        `</title>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`,
      );
    },
  };
}

// Dev server proxies /api to the FastAPI control plane so the SPA and API share an origin.
export default defineConfig({
  plugins: [react(), cspMeta()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
