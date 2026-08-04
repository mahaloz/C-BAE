import dashboardJson from "@/data/dashboard.json";

export type VerdictCategory =
  | "exact"
  | "equivalent"
  | "partial"
  | "incorrect"
  | "ungradable"
  | "infrastructure_failure";

export type TraceEvidence = {
  kind: "decompilation" | "disassembly" | "command" | "trace";
  label: string;
  eventId: string;
  command: string;
  output: string;
};

export type Selection = {
  index: number;
  address: string;
  predictedName: string;
  truthName: string | null;
  mangledName: string | null;
  category: VerdictCategory;
  graderVerdict: string | null;
  discoveredName: string | null;
  size: number | null;
  wasPreNamed: boolean;
  directDecompilationCaptured: boolean;
  decompilation: {
    status: "ok" | "error";
    text: string | null;
    backend: string;
    error: string | null;
    capturedAt: string;
  } | null;
  evidence: TraceEvidence[];
};

export type Stage = {
  durationSeconds: number;
  startedAt: string | null;
  finishedAt: string | null;
  status: string;
  usage: {
    input_tokens: number;
    cached_input_tokens: number;
    output_tokens: number;
    reasoning_output_tokens: number;
  };
  cost: { standard: number; upperBound: number } | null;
};

export type DashboardRun = {
  id: string;
  targetId: string;
  displayName: string;
  status: string;
  model: string;
  reasoningEffort: string | null;
  backend: string | null;
  binary: {
    sizeBytes: number | null;
    architecture: string | null;
    format: string | null;
    os: string;
    functionCount: number;
    sha256: string | null;
  };
  scores: {
    exactAccuracy: number;
    semanticAccuracy: number;
    counts: Record<VerdictCategory | "gradeable", number>;
    submitted: number;
  };
  reverse: Stage;
  grade: Stage;
  totalDurationSeconds: number;
  cost: {
    standard: number;
    upperBound: number;
    kind: string;
  } | null;
  tools: {
    total: number;
    shell: number;
    collaboration: number;
    web: number;
    decompilations: number;
    disassemblies: number;
    eventTypes: Record<string, number>;
  };
  audit: {
    preNamedSelections: number;
    directDecompilationsCaptured: number;
    decompilationsAvailable: number;
    selectionsWithTraceEvidence: number;
    traceAvailable: boolean;
  };
  selections: Selection[];
};

export type Dashboard = {
  schemaVersion: number;
  generatedAt: string;
  overview: {
    binaryCount: number;
    predictionCount: number;
    exactAccuracy: number;
    semanticAccuracy: number;
    averageDurationSeconds: number;
    totalCost: number | null;
    averageCost: number | null;
    totalCostUpperBound: number | null;
    costKind: string | null;
  };
  runs: DashboardRun[];
};

export const dashboard = dashboardJson as unknown as Dashboard;

export function formatPercent(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "percent",
    minimumFractionDigits: 0,
    maximumFractionDigits: 1,
  }).format(value);
}

export function formatMoney(value: number | null): string {
  if (value === null) return "Not reported";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(value);
}

export function formatDuration(seconds: number): string {
  const totalMinutes = Math.round(seconds / 60);
  if (totalMinutes < 60) return `${totalMinutes}m`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours}h ${minutes}m`;
}

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return "Unknown";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index >= 2 ? 1 : 0)} ${units[index]}`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}
