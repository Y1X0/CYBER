import "@testing-library/jest-dom/vitest";

// jsdom does not implement matchMedia, so every media query the UI asks about answers "no" by
// default — which means the tests run the full-motion path and assertions about rendered numbers
// race the count-up animation.
//
// The suite runs in the reduced-motion profile instead. That is the honest choice twice over: the
// assertions are about what the screens say, never about how they move, and reduced motion is a
// real user configuration that therefore gets exercised on every run rather than never.
window.matchMedia = ((query: string) => ({
  media: query,
  matches: query.includes("prefers-reduced-motion"),
  onchange: null,
  addListener: () => {},
  removeListener: () => {},
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => false,
})) as unknown as typeof window.matchMedia;
