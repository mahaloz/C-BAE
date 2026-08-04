import Link from "next/link";

export function SiteHeader({ compact = false }: { compact?: boolean }) {
  return (
    <header className={`site-header ${compact ? "site-header--compact" : ""}`}>
      <Link className="brand" href="/" aria-label="C-BAE evaluation overview">
        <span>
          <strong>C-BAE Results</strong>
          <small>Function recovery evaluation</small>
        </span>
      </Link>
      <div className="header-status">
        Data from preserved run artifacts
      </div>
    </header>
  );
}
