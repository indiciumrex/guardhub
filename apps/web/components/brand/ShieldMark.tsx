/**
 * The GuardHub shield mark (same geometry as packages/shared/brand/mark.svg), with
 * dark-mode colours. Decorative by default; pass `title` to expose it to assistive tech.
 */
interface ShieldMarkProps {
  className?: string;
  title?: string;
}

export function ShieldMark({ className = "h-8 w-8", title }: ShieldMarkProps) {
  return (
    <svg
      viewBox="0 0 48 48"
      className={className}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      <path
        d="M24 3.5 40.5 9.6v12.1c0 10.4-6.9 19.5-16.5 22.8C14.4 41.2 7.5 32.1 7.5 21.7V9.6Z"
        className="fill-navy-900 dark:fill-teal-400"
      />
      <path
        d="M24 3.5 40.5 9.6v12.1c0 10.4-6.9 19.5-16.5 22.8Z"
        className="fill-navy-800 dark:fill-teal-500"
      />
      <path
        d="M24 8.9 35.5 13.2v8.5c0 7.6-4.8 14.4-11.5 17.1-6.7-2.7-11.5-9.5-11.5-17.1v-8.5Z"
        fill="none"
        strokeWidth="1.2"
        strokeOpacity="0.35"
        className="stroke-teal-400 dark:stroke-navy-950"
      />
      <path
        d="m16.8 23.6 5 5 9.6-9.8"
        fill="none"
        strokeWidth="3.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="stroke-teal-400 dark:stroke-navy-950"
      />
    </svg>
  );
}
