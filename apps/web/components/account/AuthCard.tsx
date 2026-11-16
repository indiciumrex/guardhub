import type { ReactNode } from "react";

/** Centered card used by the login, register and 2FA screens. */
export function AuthCard({
  title,
  intro,
  children,
}: {
  title: string;
  intro?: string;
  children: ReactNode;
}) {
  return (
    <div className="gh-container flex justify-center py-12 sm:py-16">
      <div className="gh-card w-full max-w-md p-6 sm:p-8">
        <h1 className="text-2xl font-bold">{title}</h1>
        {intro ? <p className="gh-muted mt-2 text-sm">{intro}</p> : null}
        <div className="mt-6">{children}</div>
      </div>
    </div>
  );
}
