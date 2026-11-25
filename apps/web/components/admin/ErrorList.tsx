/** Recent errors (scan failures, degraded modules, Sentry issues) as a plain list. */
import type { ErrorItem } from "@/lib/admin-types";
import { Badge } from "./Stat";

export function ErrorList({
  items,
  when,
  none,
}: {
  items: ErrorItem[];
  when: (v: string | null) => string;
  none: string;
}) {
  return (
    <ul className="gh-panel divide-y divide-slate-200 text-sm dark:divide-navy-800">
      {items.length === 0 ? (
        <li className="gh-muted px-5 py-3">{none}</li>
      ) : (
        items.map((e, i) => (
          <li key={`${e.source}-${i}`} className="px-5 py-2.5">
            <Badge tone={e.source === "module" ? "warn" : "bad"}>{e.source}</Badge>{" "}
            <span className="font-mono text-xs">{e.title}</span>
            {e.count ? <span className="gh-muted"> ×{e.count}</span> : null}
            <span className="gh-muted block break-all text-xs">
              {e.detail} · {when(e.at)}
            </span>
          </li>
        ))
      )}
    </ul>
  );
}
