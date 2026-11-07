/** Health score drawn as a postmark: the product's signature element. */
export function ScoreStamp({ score, grade, size = 148, animate = false, label }: { score: number; grade: string; size?: number; animate?: boolean; label?: string }) {
  const color = score >= 75 ? 'var(--color-pass)' : score >= 50 ? 'var(--color-warn)' : 'var(--color-fail)';
  const id = `arc-${size}-${score}`;
  return (
    <figure
      className={`relative inline-block shrink-0 ${animate ? 'stamp-in' : ''}`}
      style={{ width: size, height: size, transform: animate ? undefined : 'rotate(-8deg)', color }}
      aria-label={`Health score ${score} out of 100, grade ${grade}`}
      role="img"
    >
      <svg viewBox="0 0 160 160" width={size} height={size} aria-hidden>
        <defs>
          <path id={id} d="M 80 80 m -58 0 a 58 58 0 1 1 116 0 a 58 58 0 1 1 -116 0" />
        </defs>
        <circle cx="80" cy="80" r="74" fill="none" stroke="currentColor" strokeWidth="3" />
        <circle cx="80" cy="80" r="47" fill="none" stroke="currentColor" strokeWidth="1.5" />
        {/* Postmark ring text: one pass around the circle, stretched to fit exactly (2πr = 364). */}
        <text fontSize="10" fontWeight="600" fill="currentColor" fontFamily="var(--font-sans)">
          <textPath href={`#${id}`} startOffset="0" textLength="356" lengthAdjust="spacing">
            {(label ?? 'Maily Flex • SPF • DKIM • DMARC').toUpperCase()} •
          </textPath>
        </text>
        <text x="80" y="86" textAnchor="middle" fontSize="38" fontWeight="700" fill="currentColor" fontFamily="var(--font-display)">
          {score}
        </text>
        <text x="80" y="108" textAnchor="middle" fontSize="13" fontWeight="600" fill="currentColor" fontFamily="var(--font-sans)">
          Grade {grade}
        </text>
      </svg>
    </figure>
  );
}
