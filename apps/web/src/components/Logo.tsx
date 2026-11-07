export function Logo({ className = '' }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 font-display text-[19px] font-bold tracking-tight ${className}`}>
      <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden>
        <rect width="32" height="32" rx="7" fill="#13213C" />
        <path d="M7 11h18v11H7z" fill="none" stroke="#F4F6FA" strokeWidth="2" />
        <path d="M7 11l9 7 9-7" fill="none" stroke="#C3343F" strokeWidth="2" />
      </svg>
      Maily Flex
    </span>
  );
}
