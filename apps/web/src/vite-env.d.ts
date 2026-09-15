/// <reference types="vite/client" />

// Declared rather than inferred: VITE_API_BASE is the one build-time input this app has, and a
// typo in it would otherwise fail at runtime in a browser instead of at compile time here.
interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
