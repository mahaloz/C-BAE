"use client";

import { useMemo, useState } from "react";
import type { Selection, VerdictCategory } from "@/lib/dashboard";
import { formatNumber } from "@/lib/dashboard";

const filters: Array<{ value: "all" | VerdictCategory; label: string }> = [
  { value: "all", label: "All" },
  { value: "exact", label: "Exact" },
  { value: "equivalent", label: "Equivalent" },
  { value: "partial", label: "Partial" },
  { value: "incorrect", label: "Incorrect" },
];

function categoryLabel(category: VerdictCategory) {
  return category.replace("_", " ");
}

export function FunctionAudit({ selections }: { selections: Selection[] }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | VerdictCategory>("all");
  const [selectedAddress, setSelectedAddress] = useState(selections[0]?.address ?? "");

  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return selections.filter((selection) => {
      if (filter !== "all" && selection.category !== filter) return false;
      if (!normalized) return true;
      return [
        selection.address,
        selection.predictedName,
        selection.truthName,
        selection.discoveredName,
      ].some((value) => value?.toLowerCase().includes(normalized));
    });
  }, [filter, query, selections]);

  const selected =
    selections.find((selection) => selection.address === selectedAddress) ??
    filtered[0] ??
    selections[0];

  function randomSample() {
    const pool = filtered.length ? filtered : selections;
    const next = pool[Math.floor(Math.random() * pool.length)];
    if (next) setSelectedAddress(next.address);
  }

  if (!selected) return null;

  return (
    <div className="audit-workbench">
      <div className="audit-toolbar">
        <label className="search-field">
          <span className="sr-only">Search selected functions</span>
          <span aria-hidden="true">⌕</span>
          <input
            type="search"
            placeholder="Search address, prediction, or truth…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <div className="filter-group" aria-label="Filter by verdict">
          {filters.map((item) => (
            <button
              className={filter === item.value ? "active" : ""}
              key={item.value}
              onClick={() => setFilter(item.value)}
              type="button"
            >
              {item.label}
            </button>
          ))}
        </div>
        <button className="sample-button" type="button" onClick={randomSample}>
          Random sample
        </button>
      </div>

      <div className="audit-grid">
        <aside className="function-list" aria-label="Model-selected functions">
          <div className="list-heading">
            <span>Selected functions</span>
            <strong>{filtered.length}/{selections.length}</strong>
          </div>
          <div className="function-list-scroll">
            {filtered.map((selection) => (
              <button
                type="button"
                key={selection.address}
                className={`function-row ${selected.address === selection.address ? "active" : ""}`}
                onClick={() => setSelectedAddress(selection.address)}
              >
                <span className="function-index">{String(selection.index).padStart(2, "0")}</span>
                <span className="function-row-main">
                  <strong>{selection.predictedName}</strong>
                  <code>{selection.address}</code>
                </span>
                <span className={`verdict-dot verdict-dot--${selection.category}`} title={categoryLabel(selection.category)} />
              </button>
            ))}
            {!filtered.length && (
              <div className="empty-list">No selected functions match this filter.</div>
            )}
          </div>
        </aside>

        <article className="evidence-panel">
          <div className="evidence-topline">
            <div>
              <div className="address-line">
                <code>{selected.address}</code>
                <span className={`verdict-badge verdict-badge--${selected.category}`}>
                  {categoryLabel(selected.category)}
                </span>
              </div>
              <h3>{selected.predictedName}</h3>
            </div>
            <span className="function-size">
              {selected.size ? `${formatNumber(selected.size)} bytes` : "Size unknown"}
            </span>
          </div>

          <div className="name-comparison">
            <div>
              <span>Model prediction</span>
              <code>{selected.predictedName}</code>
            </div>
            <div>
              <span>Authoritative name</span>
              <code>{selected.truthName ?? "Not available"}</code>
            </div>
            <div>
              <span>Name visible before the run</span>
              <code>{selected.discoveredName ?? "Unknown"}</code>
            </div>
          </div>

          <div className="audit-signals">
            <span className={selected.wasPreNamed ? "signal signal--warn" : "signal signal--ok"}>
              <i aria-hidden="true" />
              {selected.wasPreNamed ? "Pre-existing non-generic name" : "Generic pre-run name"}
            </span>
            <span className={selected.directDecompilationCaptured ? "signal signal--ok" : "signal signal--neutral"}>
              <i aria-hidden="true" />
              {selected.directDecompilationCaptured
                ? "Direct decompilation captured"
                : "No direct decompilation captured"}
            </span>
            <span className={selected.decompilation?.status === "ok" ? "signal signal--ok" : "signal signal--warn"}>
              <i aria-hidden="true" />
              {selected.decompilation?.status === "ok"
                ? "IDA pseudocode available"
                : "IDA pseudocode unavailable"}
            </span>
            <span className={selected.evidence.length ? "signal signal--ok" : "signal signal--warn"}>
              <i aria-hidden="true" />
              {selected.evidence.length
                ? `${selected.evidence.length} trace evidence ${selected.evidence.length === 1 ? "record" : "records"}`
                : "No address-level trace evidence"}
            </span>
          </div>

          <section className="pseudocode-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">IDA Pro pseudocode</p>
                <h4>Decompilation</h4>
              </div>
              <span>{selected.decompilation?.backend?.toUpperCase() ?? "IDA"}</span>
            </div>
            {selected.decompilation?.status === "ok" && selected.decompilation.text ? (
              <pre>{selected.decompilation.text}</pre>
            ) : (
              <div className="evidence-empty">
                <strong>IDA could not produce pseudocode for this function.</strong>
                <p>{selected.decompilation?.error ?? "No decompilation was cached."}</p>
              </div>
            )}
          </section>

          <div className="evidence-section-heading">
            <div>
              <p className="eyebrow">What the model saw</p>
              <h4>Original model trace</h4>
            </div>
            <p>
              Parent-agent commands and outputs mentioning this address. Captured
              evidence is not proof that an untraced subagent never inspected it.
            </p>
          </div>

          <div className="evidence-stack">
            {selected.evidence.map((item, index) => (
              <details className="trace-record" key={`${item.eventId}-${index}`} open={index === 0}>
                <summary>
                  <span className={`trace-kind trace-kind--${item.kind}`}>{item.label}</span>
                  <code>{item.eventId}</code>
                  <span aria-hidden="true">＋</span>
                </summary>
                <div className="trace-body">
                  <div>
                    <span>Command</span>
                    <pre>{item.command}</pre>
                  </div>
                  <div>
                    <span>Captured output</span>
                    <pre>{item.output}</pre>
                  </div>
                </div>
              </details>
            ))}
            {!selected.evidence.length && (
              <div className="evidence-empty">
                <strong>No per-address evidence was preserved.</strong>
                <p>
                  The prediction exists in the final submission, but this parent trace
                  contains no command or output mentioning its address.
                </p>
              </div>
            )}
          </div>
        </article>
      </div>
    </div>
  );
}
