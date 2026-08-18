// A hash router in thirty lines.
//
// Deliberately not a dependency: the app has a dozen screens and one nesting level, and adding a
// routing library would change the lockfile and the CI install for something this file does
// completely. `#/findings/<id>` is the whole grammar.

import { useEffect, useState } from "react";

export interface Route {
  screen: string;
  id: string | null;
}

export function parse(hash: string): Route {
  const clean = hash.replace(/^#\/?/, "").split("?")[0];
  const [screen, id] = clean.split("/");
  return { screen: screen || "dashboard", id: id || null };
}

export function navigate(to: string): void {
  window.location.hash = `#/${to.replace(/^\/+/, "")}`;
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parse(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parse(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
