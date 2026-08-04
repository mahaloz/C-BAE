import { SiteHeader } from "@/app/components/SiteHeader";
import Link from "next/link";
import {
  dashboard,
  formatDuration,
  formatMoney,
  formatNumber,
  formatPercent,
} from "@/lib/dashboard";

export default function Home() {
  const { overview, runs } = dashboard;

  return (
    <main>
      <div className="page-shell">
        <SiteHeader />

        <section className="hero">
          <div>
            <p className="eyebrow">Dataset overview</p>
            <h1>Function recovery results</h1>
          </div>
          <p className="hero-copy">
            Compare exact and semantic naming accuracy across {overview.binaryCount}{" binaries"},
            then inspect the model&apos;s selected functions, IDA pseudocode, and trace evidence.
          </p>
        </section>

        <section className="metric-grid" aria-label="Overall evaluation metrics">
          <article className="metric-card metric-card--accent">
            <span>Semantic recovery</span>
            <strong>{formatPercent(overview.semanticAccuracy)}</strong>
            <p>Exact + grader-equivalent names</p>
          </article>
          <article className="metric-card">
            <span>Exact recovery</span>
            <strong>{formatPercent(overview.exactAccuracy)}</strong>
            <p>Exact authoritative names</p>
          </article>
          <article className="metric-card">
            <span>Total modeled cost</span>
            <strong>{formatMoney(overview.totalCost)}</strong>
            <p>{overview.costKind ?? "Provider-reported spend"}</p>
          </article>
          <article className="metric-card">
            <span>Average end-to-end time</span>
            <strong>{formatDuration(overview.averageDurationSeconds)}</strong>
            <p>Reverse + grading per binary</p>
          </article>
        </section>

        <section className="section-block">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Accuracy profile</p>
              <h2>Recovery by binary</h2>
            </div>
            <div className="legend" aria-label="Chart legend">
              <span><i className="legend-swatch legend-swatch--semantic" />Semantic</span>
              <span><i className="legend-swatch legend-swatch--exact" />Exact</span>
            </div>
          </div>

          <div className="run-chart">
            {runs.map((run) => (
              <Link className="run-chart-row" href={`/runs/${run.id}`} key={run.id}>
                <div className="run-label">
                  <strong>{run.displayName}</strong>
                  <span>{run.model} · {run.reasoningEffort} reasoning</span>
                </div>
                <div className="bar-pair">
                  <div className="bar-track" title={`Semantic ${formatPercent(run.scores.semanticAccuracy)}`}>
                    <span className="bar bar--semantic" style={{ width: formatPercent(run.scores.semanticAccuracy) }} />
                  </div>
                  <div className="bar-track" title={`Exact ${formatPercent(run.scores.exactAccuracy)}`}>
                    <span className="bar bar--exact" style={{ width: formatPercent(run.scores.exactAccuracy) }} />
                  </div>
                </div>
                <div className="run-values">
                  <strong>{formatPercent(run.scores.semanticAccuracy)}</strong>
                  <span>{formatPercent(run.scores.exactAccuracy)} exact</span>
                </div>
                <span className="row-arrow" aria-hidden="true">↗</span>
              </Link>
            ))}
          </div>
        </section>

        <section className="section-block">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Run ledger</p>
              <h2>Cost, runtime, and auditability</h2>
            </div>
            <p className="section-note">
              {formatNumber(overview.predictionCount)} submitted function names
            </p>
          </div>

          <div className="table-wrap">
            <table className="runs-table">
              <thead>
                <tr>
                  <th>Binary</th>
                  <th>Result</th>
                  <th>Cost</th>
                  <th>Time</th>
                  <th>Tool calls</th>
                  <th>Trace</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <Link href={`/runs/${run.id}`}>
                        <strong>{run.displayName}</strong>
                        <span>{run.binary.os} · {run.binary.architecture}</span>
                      </Link>
                    </td>
                    <td>
                      <strong>{run.scores.counts.exact} exact</strong>
                      <span>{run.scores.counts.equivalent} equivalent · {run.scores.counts.partial} partial</span>
                    </td>
                    <td>
                      <strong>{formatMoney(run.cost?.standard ?? null)}</strong>
                      <span>up to {formatMoney(run.cost?.upperBound ?? null)}</span>
                    </td>
                    <td>
                      <strong>{formatDuration(run.totalDurationSeconds)}</strong>
                      <span>{formatDuration(run.reverse.durationSeconds)} reversing</span>
                    </td>
                    <td>
                      <strong>{formatNumber(run.tools.total)}</strong>
                      <span>{run.tools.decompilations} direct decompiles</span>
                    </td>
                    <td>
                      <span className={`trace-pill ${run.audit.traceAvailable ? "trace-pill--ok" : ""}`}>
                        {run.audit.traceAvailable ? "Available" : "Missing"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="site-footer">
          <span>C-BAE Results</span>
          <span>Generated from preserved evaluation artifacts</span>
          <time dateTime={dashboard.generatedAt}>
            Data refreshed {new Date(dashboard.generatedAt).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })} UTC
          </time>
        </footer>
      </div>
    </main>
  );
}
