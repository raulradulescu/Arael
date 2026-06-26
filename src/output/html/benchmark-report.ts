import * as path from 'path';
import type {
  AgentBenchmarkRecord,
  AgentBenchmarkRunResult,
  AgentVariantSummary,
  BenchmarkRecord,
  BenchmarkRunResult,
  LLMBenchmarkRecord,
  ReproducibilityMetadata
} from '../../benchmark/types';
import { badge, bar, collapsible, copyButton, searchBox, solvedOnlyToggle, statCard, table, type TableRow } from './components';
import { escapeHtml } from './escape';
import { formatGeneratedDate, renderHtmlDocument } from './layout';

export interface RenderBenchmarkHtmlOptions {
  title?: string;
  generatedAt?: Date | string;
}

export interface RenderAgentBenchmarkHtmlOptions extends RenderBenchmarkHtmlOptions {
  reportPath?: string;
}

export function renderBenchmarkHtml(result: BenchmarkRunResult, opts: RenderBenchmarkHtmlOptions = {}): string {
  const title = opts.title ?? 'Arael Benchmark Report';
  const generatedAt = opts.generatedAt ?? result.timestamp;
  const body = `
  <div class="header">
    <div class="header-content">
      <div>
        <h1>${escapeHtml(title)}</h1>
        <div class="header-meta">
          <span>Run: ${escapeHtml(result.runId)}</span>
          <span>${escapeHtml(formatGeneratedDate(generatedAt))}</span>
          <span>${escapeHtml(result.summary.sampleCount)} samples</span>
          <span>${escapeHtml(result.summary.recordCount)} runs</span>
        </div>
      </div>
      ${badge('Benchmark', 'accent')}
    </div>
  </div>
  <div class="container">
    ${renderBenchmarkSummary(result)}
    ${renderBenchmarkRecords(result.records)}
    ${result.llmRecords.length > 0 ? renderLlmRecords(result.llmRecords) : ''}
  </div>`;

  return renderHtmlDocument({ title, generatedAt, body });
}

export function renderAgentBenchmarkHtml(
  result: AgentBenchmarkRunResult,
  opts: RenderAgentBenchmarkHtmlOptions = {}
): string {
  const title = opts.title ?? 'Arael Agent Benchmark Report';
  const generatedAt = opts.generatedAt ?? result.timestamp;
  const totalDuration = result.records.reduce((sum, record) => sum + record.durationSeconds, 0);
  const body = `
  <div class="header">
    <div class="header-content">
      <div>
        <h1>${escapeHtml(title)}</h1>
        <div class="header-meta">
          <span>Run: ${escapeHtml(result.runId)}</span>
          <span>${escapeHtml(formatGeneratedDate(generatedAt))}</span>
          <span>${escapeHtml(result.summary.challengeCount)} challenges</span>
          <span>${escapeHtml(result.summary.agentCount)} agents</span>
          <span>${escapeHtml(result.summary.recordCount)} runs</span>
        </div>
      </div>
      ${badge('Agent Benchmark', 'accent')}
    </div>
  </div>
  <div class="container">
    ${renderAgentSummary(result, totalDuration)}
    ${renderAgentLeaderboard(result.summary.variants)}
    ${renderAgentRuns(result.records, opts.reportPath)}
    ${renderChallengeRollup(result.records)}
    ${result.metadata ? renderReproducibility(result.metadata) : ''}
  </div>`;

  return renderHtmlDocument({ title, generatedAt, body });
}

function renderBenchmarkSummary(result: BenchmarkRunResult): string {
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">#</span><h2>Summary</h2></div>
      <div class="grid">
        ${statCard('Samples', result.summary.sampleCount.toLocaleString(), 'Corpus size')}
        ${statCard('Successful Runs', `${result.summary.successCount}/${result.summary.recordCount}`, 'Analysis completed')}
        ${statCard('Timeouts', result.summary.timeoutCount.toLocaleString(), 'Timed out')}
        ${statCard('Avg Wall Time', formatSeconds(result.summary.averageTotalWallTimeSeconds), 'Per run')}
        ${statCard('Avg Function Recall', formatNullable(result.summary.averageFunctionRecall), 'Ground-truth metric')}
        ${statCard('Avg Classification', formatPercentValue(result.summary.averageClassificationAccuracy), 'Accuracy')}
      </div>
    </div>
  `;
}

function renderBenchmarkRecords(records: BenchmarkRecord[]): string {
  const rows = records.map(record => [
    escapeHtml(record.sampleId),
    escapeHtml(record.fileName),
    record.analysisSuccess ? badge('ok', 'success') : badge(record.timeout ? 'timeout' : 'failed', record.timeout ? 'warn' : 'danger'),
    escapeHtml(record.runIndex),
    escapeHtml(record.classification ?? ''),
    escapeHtml(record.performance.cacheHitOrMiss),
    formatSeconds(record.performance.totalWallTimeSeconds),
    escapeHtml(record.counts.functionsDetected.toLocaleString()),
    escapeHtml(record.counts.iocsDetected.toLocaleString()),
    formatNullable(record.scores.functions.recall),
    formatNullable(record.scores.behaviors.f1),
    formatNullable(record.scores.iocs.f1),
    formatNullable(record.scores.mitre.f1),
    record.errorMessage ? escapeHtml(record.errorMessage) : ''
  ]);
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">b</span><h2>Samples</h2></div>
      <div class="toolbar">${searchBox('benchmark-records-table', 'Search samples')}</div>
      ${table([
        'Sample',
        'File',
        'Status',
        'Run',
        'Classification',
        'Cache',
        'Wall Time',
        'Functions',
        'IOCs',
        'Function Recall',
        'Behavior F1',
        'IOC F1',
        'MITRE F1',
        'Error'
      ], rows, { id: 'benchmark-records-table', sortable: true })}
    </div>
  `;
}

function renderLlmRecords(records: LLMBenchmarkRecord[]): string {
  const rows = records.map(record => [
    escapeHtml(record.sampleId),
    escapeHtml(record.llmProvider),
    escapeHtml(record.llmModel),
    escapeHtml(record.questionId),
    formatSeconds(record.llmLatencySeconds),
    escapeHtml(totalTokens(record.inputTokens, record.outputTokens)),
    formatCost(record.costUsd),
    formatNullable(record.llmAnswerScore),
    escapeHtml(record.answer.slice(0, 180))
  ]);
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">?</span><h2>LLM Questions</h2></div>
      <div class="toolbar">${searchBox('llm-records-table', 'Search LLM records')}</div>
      ${table(['Sample', 'Provider', 'Model', 'Question', 'Latency', 'Tokens', 'Cost', 'Score', 'Answer Preview'], rows, {
        id: 'llm-records-table',
        sortable: true
      })}
    </div>
  `;
}

function renderAgentSummary(result: AgentBenchmarkRunResult, totalDuration: number): string {
  const summary = result.summary;
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">#</span><h2>Summary</h2></div>
      <div class="grid">
        ${statCard('Solved', `${summary.solveCount}/${summary.recordCount}`, `${formatPercent(summary.solveCount, summary.recordCount)} solve rate`)}
        ${statCard('Graded', summary.gradedCount.toLocaleString(), 'Ground-truth checked')}
        ${statCard('Challenges', summary.challengeCount.toLocaleString(), 'Targets')}
        ${statCard('Agents', summary.agentCount.toLocaleString(), 'Variants')}
        ${statCard('Total Tokens', formatInteger(summary.totalTokens), 'All runs')}
        ${statCard('Total Cost', formatCost(summary.totalCostUsd), 'Estimated USD')}
        ${statCard('Avg Duration', formatSeconds(summary.averageDurationSeconds), 'Per run')}
        ${statCard('Total Duration', formatSeconds(totalDuration), 'Sum of run durations')}
      </div>
    </div>
  `;
}

function renderAgentLeaderboard(variants: AgentVariantSummary[]): string {
  const sorted = [...variants].sort((left, right) => {
    const rateDiff = (right.solveRate ?? -1) - (left.solveRate ?? -1);
    if (rateDiff !== 0) {
      return rateDiff;
    }
    return (left.totalCostUsd ?? Number.POSITIVE_INFINITY) - (right.totalCostUsd ?? Number.POSITIVE_INFINITY);
  });
  const rows = sorted.map(variant => [
    escapeHtml(variant.engine),
    escapeHtml(variant.model),
    variant.araelMcp ? badge('+arael', 'accent') : badge('bare', 'muted'),
    escapeHtml(variant.recordCount.toLocaleString()),
    escapeHtml(variant.solveCount.toLocaleString()),
    bar(variant.solveRate === null ? null : variant.solveRate * 100, variant.solveRate === null ? 'N/A' : formatPercentValue(variant.solveRate)),
    formatSeconds(variant.averageDurationSeconds),
    formatInteger(variant.totalTokens),
    formatCost(variant.totalCostUsd)
  ]);
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">^</span><h2>Leaderboard</h2></div>
      ${table(['Engine', 'Model', 'Arael', 'Runs', 'Solves', 'Solve Rate', 'Avg Duration', 'Tokens', 'Cost'], rows, {
        id: 'agent-leaderboard-table',
        sortable: true
      })}
    </div>
  `;
}

function renderAgentRuns(records: AgentBenchmarkRecord[], reportPath?: string): string {
  const rows: TableRow[] = records.map(record => ({
    attrs: { 'data-solved': isAgentSolved(record) ? 'true' : 'false' },
    cells: [
      escapeHtml(record.challengeId),
      escapeHtml(agentVariantLabel(record)),
      escapeHtml(record.runIndex),
      record.success ? badge('ok', 'success') : badge(record.timedOut ? 'timeout' : 'failed', record.timedOut ? 'warn' : 'danger'),
      solvedBadge(record),
      record.flagFound ? badge('yes', 'success') : badge('no', 'muted'),
      flagCorrectBadge(record.flagCorrect),
      record.flag ? `<span class="mono">${escapeHtml(record.flag)}</span>${copyButton(record.flag, 'Copy flag')}` : '',
      formatSeconds(record.durationSeconds),
      formatInteger(record.totalTokens),
      formatCost(record.costUsd),
      artifactLinks(record, reportPath)
    ]
  }));
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">r</span><h2>Runs</h2></div>
      <div class="toolbar">
        <div class="toolbar-group">
          ${searchBox('agent-runs-table', 'Search runs')}
          ${solvedOnlyToggle('agent-runs-table')}
        </div>
      </div>
      ${table([
        'Challenge',
        'Variant',
        'Run',
        'Status',
        'Solved',
        'Flag Found',
        'Flag Correct',
        'Flag',
        'Duration',
        'Tokens',
        'Cost',
        'Artifacts'
      ], rows, { id: 'agent-runs-table', sortable: true })}
    </div>
  `;
}

function renderChallengeRollup(records: AgentBenchmarkRecord[]): string {
  const byChallenge = new Map<string, AgentBenchmarkRecord[]>();
  for (const record of records) {
    const list = byChallenge.get(record.challengeId) ?? [];
    list.push(record);
    byChallenge.set(record.challengeId, list);
  }
  const panels = Array.from(byChallenge.entries())
    .sort(([left], [right]) => left.localeCompare(right, undefined, { numeric: true }))
    .map(([challengeId, challengeRecords]) => {
      const solvers = challengeRecords.filter(isAgentSolved);
      const rows = challengeRecords.map(record => [
        escapeHtml(agentVariantLabel(record)),
        escapeHtml(record.runIndex),
        solvedBadge(record),
        record.flag ? `<span class="mono">${escapeHtml(record.flag)}</span>` : '',
        formatSeconds(record.durationSeconds),
        formatCost(record.costUsd)
      ]);
      const inner = `
        <p class="muted">${escapeHtml(solvers.length)} of ${escapeHtml(challengeRecords.length)} runs solved this challenge.</p>
        ${table(['Variant', 'Run', 'Solved', 'Flag', 'Duration', 'Cost'], rows, { sortable: true })}
      `;
      return collapsible(`${challengeId} (${solvers.length}/${challengeRecords.length} solved)`, inner, solvers.length > 0);
    }).join('');

  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">c</span><h2>Per-Challenge Rollup</h2></div>
      ${panels}
    </div>
  `;
}

function renderReproducibility(meta: ReproducibilityMetadata): string {
  const rows: Array<[string, string]> = [
    ['Generated', meta.generatedAt],
    ['Arael version', meta.araelVersion],
    ['Git commit', meta.gitCommit ?? '—'],
    ['Node', meta.node],
    ['Platform', `${meta.platform} ${meta.arch} (${meta.osType} ${meta.osRelease})`],
    ['CPUs / Memory', `${meta.cpuCount} cores / ${meta.totalMemoryMb} MB`],
    ['Working dir', meta.cwd],
    ['Agents', meta.agents.join(', ')],
    ['Runs / Concurrency', `${meta.runs} / ${meta.concurrency}`],
    ['Timeout', `${meta.timeoutSeconds}s`],
    ['Ollama URL', meta.ollamaUrl],
    ['Prompt source', meta.promptSource],
    ['Prompt sha256', meta.promptSha256],
    ['Pricing file', meta.pricingFile ?? '—'],
    ['Pricing sha256', meta.pricingSha256 ?? '—'],
    ['Ground truth file', meta.groundTruthFile ?? '—'],
    ['Ground truth sha256', meta.groundTruthSha256 ?? '—'],
    ['GHIDRA_PATH', meta.ghidraPath ?? '—'],
    ['ARAEL_PYTHON', meta.araelPython ?? '—'],
    ['Arael server', meta.araelServerPath ?? '—']
  ];
  const body = table(
    ['Field', 'Value'],
    rows.map(([key, value]) => [escapeHtml(key), `<span class="mono">${escapeHtml(value)}</span>`])
  );
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">i</span><h2>Run Environment</h2></div>
      ${collapsible('Reproducibility metadata', body, false)}
    </div>
  `;
}

function artifactLinks(record: AgentBenchmarkRecord, reportPath?: string): string {
  const links: string[] = [];
  if (record.stdoutPath) {
    links.push(`<a href="${escapeHtml(relativeArtifactPath(record.stdoutPath, reportPath))}">stdout</a>`);
    links.push(`<a href="${escapeHtml(relativeArtifactPath(recordPathFromStdout(record.stdoutPath), reportPath))}">record</a>`);
  }
  if (record.stderrPath) {
    links.push(`<a href="${escapeHtml(relativeArtifactPath(record.stderrPath, reportPath))}">stderr</a>`);
  }
  return links.length > 0 ? links.join(' · ') : '<span class="muted">none</span>';
}

function relativeArtifactPath(filePath: string, reportPath?: string): string {
  if (!reportPath) {
    return filePath.replace(/\\/g, '/');
  }
  const fromDir = path.dirname(path.resolve(reportPath));
  return path.relative(fromDir, path.resolve(filePath)).replace(/\\/g, '/');
}

function recordPathFromStdout(stdoutPath: string): string {
  return stdoutPath.endsWith('.stdout.txt')
    ? stdoutPath.slice(0, -'.stdout.txt'.length) + '.record.json'
    : `${stdoutPath}.record.json`;
}

function agentVariantLabel(record: AgentBenchmarkRecord): string {
  return `${record.agent}:${record.model}${record.araelMcp ? '+arael' : ''}`;
}

function isAgentSolved(record: AgentBenchmarkRecord): boolean {
  return record.flagCorrect === true || (record.flagCorrect === null && record.flagFound);
}

function solvedBadge(record: AgentBenchmarkRecord): string {
  if (record.flagCorrect === true) {
    return badge('yes', 'success');
  }
  if (record.flagCorrect === false) {
    return badge('no', 'danger');
  }
  return record.flagFound ? badge('flag?', 'warn') : badge('no', 'muted');
}

function flagCorrectBadge(value: boolean | null): string {
  if (value === true) {
    return badge('yes', 'success');
  }
  if (value === false) {
    return badge('no', 'danger');
  }
  return badge('ungraded', 'muted');
}

function totalTokens(inputTokens: number | null, outputTokens: number | null): string {
  const total = (inputTokens ?? 0) + (outputTokens ?? 0);
  return total > 0 ? total.toLocaleString() : '';
}

function formatSeconds(value: number | null): string {
  return value === null ? '' : `${value.toFixed(3)}s`;
}

function formatPercent(part: number, whole: number): string {
  return whole === 0 ? '0%' : `${((part / whole) * 100).toFixed(0)}%`;
}

function formatPercentValue(value: number | null): string {
  return value === null ? '' : `${(value * 100).toFixed(0)}%`;
}

function formatNullable(value: number | boolean | null): string {
  if (value === null) {
    return '';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  return value.toFixed(3);
}

function formatInteger(value: number | null): string {
  return value === null ? '' : Math.round(value).toLocaleString('en-US');
}

function formatCost(value: number | null): string {
  return value === null ? '' : `$${value.toFixed(4)}`;
}
