import type {
  AgentBenchmarkFormat,
  AgentBenchmarkRunResult,
  AgentBenchmarkRecord,
  BenchmarkFormat,
  BenchmarkRecord,
  BenchmarkRunResult,
  LLMBenchmarkRecord
} from '../types';
import { renderAgentBenchmarkHtml, renderBenchmarkHtml } from '../../output/html';

export interface BenchmarkReportOptions {
  outputPath?: string;
  title?: string;
}

export function formatBenchmarkResult(
  result: BenchmarkRunResult,
  format: BenchmarkFormat,
  options: BenchmarkReportOptions = {}
): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify(result, null, 2)}\n`;
    case 'jsonl':
      return formatJsonl(result);
    case 'csv':
      return formatCsv(result);
    case 'markdown':
      return formatMarkdown(result);
    case 'latex':
      return formatLatex(result);
    case 'html':
      return renderBenchmarkHtml(result, { title: options.title });
  }
}

export function formatAgentBenchmarkResult(
  result: AgentBenchmarkRunResult,
  format: AgentBenchmarkFormat,
  options: BenchmarkReportOptions = {}
): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify(result, null, 2)}\n`;
    case 'jsonl':
      return `${result.records.map(record => JSON.stringify(record)).join('\n')}\n`;
    case 'csv':
      return formatAgentCsv(result);
    case 'markdown':
      return formatAgentMarkdown(result);
    case 'html':
      return renderAgentBenchmarkHtml(result, {
        title: options.title,
        reportPath: options.outputPath
      });
  }
}

function formatJsonl(result: BenchmarkRunResult): string {
  const lines = [
    ...result.records.map(record => JSON.stringify({ type: 'sample', ...record })),
    ...result.llmRecords.map(record => JSON.stringify({ type: 'llm', ...record }))
  ];
  return `${lines.join('\n')}\n`;
}

function formatAgentCsv(result: AgentBenchmarkRunResult): string {
  const headers = [
    'run_id',
    'challenge_id',
    'agent',
    'model',
    'arael_mcp',
    'run_index',
    'success',
    'solved',
    'flag_found',
    'flag_correct',
    'flag',
    'exit_code',
    'timed_out',
    'duration_seconds',
    'input_tokens',
    'output_tokens',
    'total_tokens',
    'cost_usd',
    'stdout_path',
    'stderr_path',
    'dry_run'
  ];
  const rows = [
    headers,
    ...result.records.map(agentRecordToCsvRow)
  ];
  return `${rows.map(row => row.map(csvCell).join(',')).join('\n')}\n`;
}

function agentRecordToCsvRow(record: AgentBenchmarkRecord): Array<string | number | boolean | null> {
  return [
    record.runId,
    record.challengeId,
    record.agent,
    record.model,
    record.araelMcp,
    record.runIndex,
    record.success,
    isAgentSolved(record),
    record.flagFound,
    record.flagCorrect,
    record.flag,
    record.exitCode,
    record.timedOut,
    record.durationSeconds,
    record.inputTokens,
    record.outputTokens,
    record.totalTokens,
    record.costUsd,
    record.stdoutPath,
    record.stderrPath,
    record.dryRun
  ];
}

/** Mirror of the runner's solve rule: graded correct, or flag detected when ungraded. */
function isAgentSolved(record: AgentBenchmarkRecord): boolean {
  return record.flagCorrect === true || (record.flagCorrect === null && record.flagFound);
}

function formatAgentMarkdown(result: AgentBenchmarkRunResult): string {
  const lines = [
    '# Arael Agent Benchmark Report',
    '',
    `Run ID: \`${result.runId}\``,
    `Timestamp: \`${result.timestamp}\``,
    '',
    '## Summary',
    '',
    `- Challenges: ${result.summary.challengeCount}`,
    `- Agents: ${result.summary.agentCount}`,
    `- Records: ${result.summary.recordCount}`,
    `- Solved: ${result.summary.solveCount} / ${result.summary.recordCount} (${formatPercent(result.summary.solveCount, result.summary.recordCount)})`,
    `- Graded vs ground truth: ${result.summary.gradedCount}`,
    `- Successes: ${result.summary.successCount}`,
    `- Failures: ${result.summary.failureCount}`,
    `- Timeouts: ${result.summary.timeoutCount}`,
    `- Avg duration: ${formatNullable(result.summary.averageDurationSeconds, 's')}`,
    `- Total tokens: ${formatInteger(result.summary.totalTokens)}`,
    `- Avg tokens: ${formatInteger(result.summary.averageTokens)}`,
    `- Total cost: ${formatCost(result.summary.totalCostUsd)}`
  ];

  if (result.summary.variants.length > 0) {
    lines.push(
      '',
      '## Leaderboard (by variant)',
      '',
      '| Agent | Model | Arael | Runs | Solved | Solve Rate | Avg Time (s) | Tokens | Cost USD |',
      '|---|---|:---:|---:|---:|---:|---:|---:|---:|'
    );
    for (const variant of result.summary.variants) {
      lines.push([
        variant.engine,
        escapeMarkdown(variant.model),
        variant.araelMcp ? 'yes' : 'no',
        String(variant.recordCount),
        String(variant.solveCount),
        variant.solveRate === null ? '' : formatPercent(variant.solveCount, variant.recordCount),
        formatNullable(variant.averageDurationSeconds),
        formatInteger(variant.totalTokens),
        formatCost(variant.totalCostUsd)
      ].join(' | ').replace(/^/, '| ').concat(' |'));
    }
  }

  lines.push(
    '',
    '## Runs',
    '',
    '| Challenge | Agent | Model | Arael | Status | Solved | Flag | Time (s) | Tokens | Cost USD | Output |',
    '|---|---|---|:---:|---:|:---:|---|---:|---:|---:|---|'
  );

  for (const record of result.records) {
    lines.push([
      escapeMarkdown(record.challengeId),
      record.agent,
      escapeMarkdown(record.model),
      record.araelMcp ? 'yes' : 'no',
      record.timedOut ? 'timeout' : record.success ? 'ok' : 'failed',
      formatSolved(record),
      record.flag ? `\`${escapeMarkdown(record.flag)}\`` : '',
      fixed(record.durationSeconds),
      formatInteger(record.totalTokens),
      formatCost(record.costUsd),
      record.stdoutPath ? `\`${escapeMarkdown(record.stdoutPath)}\`` : escapeMarkdown(record.outputPreview)
    ].join(' | ').replace(/^/, '| ').concat(' |'));
  }

  return `${lines.join('\n')}\n`;
}

function formatSolved(record: AgentBenchmarkRecord): string {
  if (record.flagCorrect === true) {
    return 'yes';
  }
  if (record.flagCorrect === false) {
    return 'no';
  }
  return record.flagFound ? 'flag?' : '';
}

function formatPercent(part: number, whole: number): string {
  return whole === 0 ? '' : `${((part / whole) * 100).toFixed(0)}%`;
}

function formatCost(value: number | null): string {
  return value === null ? '' : `$${value.toFixed(4)}`;
}

function formatCsv(result: BenchmarkRunResult): string {
  const headers = [
    'type',
    'run_id',
    'sample_id',
    'file_name',
    'run_index',
    'success',
    'timeout',
    'classification',
    'ground_truth_label',
    'analysis_time_seconds',
    'total_wall_time_seconds',
    'peak_memory_mb',
    'cache',
    'speedup_ratio',
    'functions_detected',
    'strings_detected',
    'imports_detected',
    'iocs_detected',
    'behaviors_detected',
    'mitre_detected',
    'function_recall',
    'behavior_f1',
    'ioc_f1',
    'mitre_f1',
    'classification_correct',
    'llm_provider',
    'llm_model',
    'question_id',
    'llm_latency_seconds',
    'input_tokens',
    'output_tokens',
    'cost_usd',
    'llm_answer_score',
    'hallucination_count'
  ];

  const rows = [
    headers,
    ...result.records.map(recordToCsvRow),
    ...result.llmRecords.map(llmRecordToCsvRow)
  ];

  return `${rows.map(row => row.map(csvCell).join(',')).join('\n')}\n`;
}

function recordToCsvRow(record: BenchmarkRecord): Array<string | number | boolean | null> {
  return [
    'sample',
    record.runId,
    record.sampleId,
    record.fileName,
    record.runIndex,
    record.analysisSuccess,
    record.timeout,
    record.classification,
    record.groundTruthLabel,
    record.performance.analysisTimeSeconds,
    record.performance.totalWallTimeSeconds,
    record.performance.peakMemoryMb,
    record.performance.cacheHitOrMiss,
    record.performance.speedupRatio,
    record.counts.functionsDetected,
    record.counts.stringsDetected,
    record.counts.importsDetected,
    record.counts.iocsDetected,
    record.counts.behaviorsDetected,
    record.counts.mitreTechniquesDetected,
    record.scores.functions.recall,
    record.scores.behaviors.f1,
    record.scores.iocs.f1,
    record.scores.mitre.f1,
    record.scores.classificationCorrect,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null
  ];
}

function llmRecordToCsvRow(record: LLMBenchmarkRecord): Array<string | number | boolean | null> {
  return [
    'llm',
    record.runId,
    record.sampleId,
    record.fileName,
    null,
    true,
    false,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    record.llmProvider,
    record.llmModel,
    record.questionId,
    record.llmLatencySeconds,
    record.inputTokens,
    record.outputTokens,
    record.costUsd,
    record.llmAnswerScore,
    record.llmHallucinationCount
  ];
}

function formatMarkdown(result: BenchmarkRunResult): string {
  const lines = [
    '# Arael Benchmark Report',
    '',
    `Run ID: \`${result.runId}\``,
    `Timestamp: \`${result.timestamp}\``,
    '',
    '## Summary',
    '',
    `- Samples: ${result.summary.sampleCount}`,
    `- Records: ${result.summary.recordCount}`,
    `- Successes: ${result.summary.successCount}`,
    `- Failures: ${result.summary.failureCount}`,
    `- Timeouts: ${result.summary.timeoutCount}`,
    `- Avg total wall time: ${formatNullable(result.summary.averageTotalWallTimeSeconds, 's')}`,
    `- Avg function recall: ${formatNullable(result.summary.averageFunctionRecall)}`,
    `- Avg behavior F1: ${formatNullable(result.summary.averageBehaviorF1)}`,
    `- Avg IOC F1: ${formatNullable(result.summary.averageIocF1)}`,
    `- Avg MITRE F1: ${formatNullable(result.summary.averageMitreF1)}`,
    '',
    '## Samples',
    '',
    '| Sample | Status | Time (s) | Cache | Functions | IOC F1 | Behavior F1 | MITRE F1 |',
    '|---|---:|---:|---|---:|---:|---:|---:|'
  ];

  for (const record of result.records) {
    lines.push([
      escapeMarkdown(record.sampleId),
      record.analysisSuccess ? 'ok' : 'failed',
      fixed(record.performance.totalWallTimeSeconds),
      record.performance.cacheHitOrMiss,
      String(record.counts.functionsDetected),
      formatNullable(record.scores.iocs.f1),
      formatNullable(record.scores.behaviors.f1),
      formatNullable(record.scores.mitre.f1)
    ].join(' | ').replace(/^/, '| ').concat(' |'));
  }

  if (result.llmRecords.length > 0) {
    lines.push('', '## LLM Questions', '', '| Sample | Provider | Model | Question | Score | Tokens | Cost USD |', '|---|---|---|---|---:|---:|---:|');
    for (const record of result.llmRecords) {
      const tokens = (record.inputTokens ?? 0) + (record.outputTokens ?? 0);
      lines.push([
        escapeMarkdown(record.sampleId),
        escapeMarkdown(record.llmProvider),
        escapeMarkdown(record.llmModel),
        escapeMarkdown(record.questionId),
        formatNullable(record.llmAnswerScore),
        tokens || '',
        formatNullable(record.costUsd)
      ].join(' | ').replace(/^/, '| ').concat(' |'));
    }
  }

  return `${lines.join('\n')}\n`;
}

function formatLatex(result: BenchmarkRunResult): string {
  const lines = [
    '\\begin{table}[ht]',
    '\\centering',
    '\\begin{tabular}{lrrrr}',
    '\\hline',
    'Sample & Time (s) & Functions & IOC F1 & MITRE F1 \\\\',
    '\\hline'
  ];

  for (const record of result.records) {
    lines.push(`${latexCell(record.sampleId)} & ${fixed(record.performance.totalWallTimeSeconds)} & ${record.counts.functionsDetected} & ${formatNullable(record.scores.iocs.f1)} & ${formatNullable(record.scores.mitre.f1)} \\\\`);
  }

  lines.push(
    '\\hline',
    '\\end{tabular}',
    '\\caption{Arael benchmark results}',
    '\\end{table}',
    ''
  );

  return lines.join('\n');
}

function csvCell(value: string | number | boolean | null): string {
  if (value === null || value === undefined) {
    return '';
  }
  const text = String(value);
  if (!/[",\n\r]/.test(text)) {
    return text;
  }
  return `"${text.replace(/"/g, '""')}"`;
}

function fixed(value: number | null): string {
  return value === null ? '' : value.toFixed(3);
}

function formatNullable(value: number | boolean | null, suffix = ''): string {
  if (value === null) {
    return '';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  return `${value.toFixed(3)}${suffix}`;
}

function formatInteger(value: number | null): string {
  return value === null ? '' : Math.round(value).toLocaleString('en-US');
}

function escapeMarkdown(value: string): string {
  return value.replace(/\|/g, '\\|');
}

function latexCell(value: string): string {
  return value.replace(/[\\&%$#_{}~^]/g, match => `\\${match}`);
}
