/**
 * GuardHub logo: shield mark + wordmark. The product name is a brand constant and is not
 * translated (see packages/shared/brand/README.md).
 */
import { ShieldMark } from "./ShieldMark";

export const BRAND_NAME = "GuardHub";
export const COMPANY_NAME = "HKSolutions";

interface LogoProps {
  className?: string;
  /** Hide the wordmark and show only the shield (it then gets an accessible name). */
  markOnly?: boolean;
}

export function Logo({ className = "", markOnly = false }: LogoProps) {
  if (markOnly) return <ShieldMark className={className || "h-8 w-8"} title={BRAND_NAME} />;
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <ShieldMark className="h-8 w-8 shrink-0" />
      <span className="text-xl font-bold tracking-tight text-navy-900 dark:text-white">
        Guard<span className="text-teal-700 dark:text-teal-300">Hub</span>
      </span>
    </span>
  );
}
