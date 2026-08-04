import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { SiteHeader } from "@/app/components/SiteHeader";
import {
  dashboard,
  formatBytes,
  formatDuration,
  formatMoney,
  formatNumber,
  formatPercent,
} from "@/lib/dashboard";
import { FunctionAudit } from "./FunctionAudit";

type PageProps = { params: Promise<{ id: string }> };

export const dynamicParams = false;

export function generateStaticParams() {
  return dashboard.runs.map((run) => ({ id: run.id }));
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { id } = await params;
  const run = dashboard.runs.find((item) => item.id === id);
  return { title: run?.displayName ?? "Run not found" };
}

export default async function RunDetail({ params }: PageProps) {
  const { id } = await params;
  const run = dashboard.runs.find((item) => item.id === id);
  if (!run) notFound();

  const semanticCount = run.scores.counts.exact + run.scores.counts.equivalent;

  return (
    <main>
      <div className="page-shell page-shell--detail">
        <SiteHeader compact />

        <nav className="breadcrumbs" aria-label="Breadcrumb">
          <Link href="/">Dataset overview</Link>
          <span>/</span>
          <span>Run detail</span>
        </nav>

        <section className="run-hero">
          <div className="run-title-block">
            <div className="run-kicker">
              <span className="platform-chip">{run.binary.os}</span>
              <span>{run.binary.format?.toUpperCase()} · {run.binary.architecture}</span>
            </div>
            <h1>{run.displayName}</h1>
            <code className="run-id">{run.id}</code>
          </div>
          <div className="hero-score">
            <strong>{formatPercent(run.scores.semanticAccuracy)}</strong>
            <span>semantic accuracy</span>
          </div>
        </section>

        <section className="binary-facts" aria-label="Binary facts">
          <div><span>Size</span><strong>{formatBytes(run.binary.sizeBytes)}</strong></div>
          <div><span>Architecture</span><strong>{run.binary.architecture}</strong></div>
          <div><span>Operating system</span><strong>{run.binary.os}</strong></div>
          <div><span>Cataloged functions</span><strong>{formatNumber(run.binary.functionCount)}</strong></div>
          <div className="hash-fact"><span>SHA-256</span><code>{run.binary.sha256}</code></div>
        </section>

        <section className="run-stat-grid" aria-label="Run statistics">
          <article>
            <span>Exact</span>
            <strong>{run.scores.counts.exact}<small> / {run.scores.submitted}</small></strong>
            <p>{formatPercent(run.scores.exactAccuracy)} exact accuracy</p>
          </article>
          <article>
            <span>Semantically recovered</span>
            <strong>{semanticCount}<small> / {run.scores.submitted}</small></strong>
            <p>{run.scores.counts.equivalent} grader-equivalent</p>
          </article>
          <article>
            <span>Tool calls</span>
            <strong>{formatNumber(run.tools.total)}</strong>
            <p>{run.tools.shell} shell · {run.tools.collaboration} collaboration · {run.tools.web} web</p>
          </article>
          <article>
            <span>Modeled cost</span>
            <strong>{formatMoney(run.cost?.standard ?? null)}</strong>
            <p>{run.cost?.kind ?? "No cost data"}</p>
          </article>
          <article>
            <span>Total time</span>
            <strong>{formatDuration(run.totalDurationSeconds)}</strong>
            <p>{run.chooser ? `${formatDuration(run.chooser.durationSeconds)} choose · ` : ""}{formatDuration(run.reverse.durationSeconds)} reverse · {formatDuration(run.grade.durationSeconds)} grade</p>
          </article>
          <article>
            <span>Model</span>
            <strong className="model-name">{run.model}</strong>
            <p>{run.reasoningEffort} reasoning · {run.backend?.toUpperCase()}</p>
          </article>
        </section>

        <section className="audit-intro">
          <div>
            <p className="eyebrow">Selection audit</p>
            <h2>Inspect the 100 functions {run.chooser ? "the chooser selected" : "the model chose"}</h2>
          </div>
          <div className="audit-summary">
            <span><strong>{run.audit.preNamedSelections}</strong> pre-named</span>
            <span><strong>{run.audit.decompilationsAvailable}</strong> IDA decompilations</span>
            <span><strong>{run.audit.selectionsWithTraceEvidence}</strong> with trace evidence</span>
          </div>
        </section>

        <FunctionAudit selections={run.selections} />

        <footer className="site-footer">
          <Link href="/">← All evaluated binaries</Link>
          <span>{run.model} · {run.reasoningEffort} · {run.backend}</span>
          <span>Reverse trace: {run.audit.traceAvailable ? "available" : "missing"}</span>
        </footer>
      </div>
    </main>
  );
}
