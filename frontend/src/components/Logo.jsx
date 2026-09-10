import { useState } from "react";

/**
 * Brand logo. Drop your logo file into frontend/public/ as logo.png
 * (or logo.svg / logo.jpg / logo.webp) and it's picked up automatically;
 * until then the favicon fallback is shown.
 */
const CANDIDATES = ["/logo.png", "/logo.svg", "/logo.jpg", "/logo.jpeg", "/logo.webp"];

export default function Logo({ className = "h-9 w-9 rounded-lg", alt = "ComplianceForge" }) {
  const [idx, setIdx] = useState(0);
  if (idx < CANDIDATES.length) {
    return (
      <img
        src={CANDIDATES[idx]}
        alt={alt}
        className={className}
        onError={() => setIdx((i) => i + 1)}
      />
    );
  }
  return <img src="/favicon.svg" alt={alt} className={className} />;
}
