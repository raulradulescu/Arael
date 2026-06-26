import type { AnalysisResult, FunctionInfo, ImportCapability, ImportInfo, SectionInfo, StringInfo } from '../schema';
import { badge, bar, collapsible, copyButton, searchBox, statCard, table } from './components';
import { escapeHtml } from './escape';
import { formatGeneratedDate, renderHtmlDocument } from './layout';

export interface RenderAnalysisHtmlOptions {
  title?: string;
  generatedAt?: Date | string;
  sourceLabel?: string;
}

export function renderAnalysisHtml(result: AnalysisResult, opts: RenderAnalysisHtmlOptions = {}): string {
  const reportTitle = opts.title ?? `Analysis Report: ${result.binary.filename}`;
  const generatedAt = opts.generatedAt;
  const capabilities = summarizeCapabilities(result);
  const riskLevel = determineRiskLevel(capabilities.names);
  const sections = result.sections ?? [];
  const suspiciousSections = sections.filter(isSuspiciousSection);
  const exportsCount = result.exports?.length ?? 0;
  const interestingStrings = result.strings.filter(isInterestingString).slice(0, 100);
  const topFunctions = [...result.functions]
    .filter(func => !func.isThunk && !func.isExternal)
    .sort((left, right) => right.size - left.size)
    .slice(0, 100);
  const localFunctionsBySize = [...result.functions]
    .filter(func => !func.isThunk && !func.isExternal)
    .sort((left, right) => right.size - left.size);
  const detailFunctions = localFunctionsBySize.slice(0, 50);

  const body = `
  <div class="header">
    <div class="header-content">
      <div>
        <h1>${escapeHtml(reportTitle)}</h1>
        <div class="header-meta">
          <span>${escapeHtml(formatGeneratedDate(generatedAt))}</span>
          <span>${escapeHtml(result.binary.format)} ${escapeHtml(result.binary.architecture)}${result.binary.bits ? ` (${escapeHtml(result.binary.bits)}-bit)` : ''}</span>
          <span>${escapeHtml(formatBytes(result.binary.size))}</span>
          ${opts.sourceLabel ? `<span>Source: ${escapeHtml(opts.sourceLabel)}</span>` : ''}
        </div>
      </div>
      ${badge(riskLabel(riskLevel), riskLevel === 'high' ? 'danger' : riskLevel === 'medium' ? 'warn' : 'success')}
    </div>
  </div>

  <div class="container">
    <div class="section">
      <div class="section-header"><span class="section-icon">i</span><h2>Overview</h2></div>
      <div class="grid">
        ${statCard('Functions', result.functions.length.toLocaleString(), 'Total analyzed')}
        ${statCard('Strings', result.strings.length.toLocaleString(), 'Extracted')}
        ${statCard('Imports', result.imports.length.toLocaleString(), 'External symbols')}
        ${statCard('Exports', exportsCount.toLocaleString(), 'Public symbols')}
      </div>
    </div>

    <div class="section">
      <div class="section-header"><span class="section-icon">#</span><h2>Binary Details</h2></div>
      <div class="grid grid-2">
        <div class="card">
          <div class="card-title">File Information</div>
          ${infoRow('Filename', escapeHtml(result.binary.filename))}
          ${infoRow('Path', escapeHtml(result.binary.filepath))}
          ${infoRow('Format', escapeHtml(result.binary.format))}
          ${infoRow('Architecture', `${escapeHtml(result.binary.architecture)}${result.binary.bits ? ` (${escapeHtml(result.binary.bits)}-bit)` : ''}`)}
          ${infoRow('Endianness', escapeHtml(result.binary.endianness))}
          ${infoRow('Entry Point', code(result.binary.entryPoint))}
          ${infoRow('Image Base', code(result.binary.imageBase))}
          ${infoRow('Size', escapeHtml(formatBytes(result.binary.size)))}
        </div>
        <div class="card">
          <div class="card-title">Packing Analysis</div>
          ${packingSummary(result)}
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-header"><span class="section-icon">@</span><h2>Hashes</h2></div>
      <div class="card">
        ${hashRow('MD5', result.binary.hashes.md5)}
        ${hashRow('SHA1', result.binary.hashes.sha1)}
        ${hashRow('SHA256', result.binary.hashes.sha256)}
      </div>
    </div>

    ${capabilities.names.size > 0 ? renderCapabilities(capabilities) : ''}
    ${sections.length > 0 ? renderSections(sections, suspiciousSections.length) : ''}
    ${renderFunctions(topFunctions)}
    ${renderFunctionDetails(result, detailFunctions, localFunctionsBySize.length)}
    ${interestingStrings.length > 0 ? renderStrings(interestingStrings) : ''}
    ${renderImports(result)}
  </div>`;

  return renderHtmlDocument({
    title: reportTitle,
    generatedAt,
    body
  });
}

type RiskLevel = 'low' | 'medium' | 'high';

function summarizeCapabilities(result: AnalysisResult): {
  names: Set<string>;
  counts: Record<string, number>;
} {
  const names = new Set<string>();
  const counts: Record<string, number> = {};
  for (const imp of result.imports) {
    for (const capability of imp.capabilities ?? []) {
      names.add(capability);
      counts[capability] = (counts[capability] ?? 0) + 1;
    }
  }
  return { names, counts };
}

function determineRiskLevel(capabilities: Set<string>): RiskLevel {
  const highRiskCaps = ['Injection', 'AntiDebug', 'Credential', 'Keylogger'];
  const mediumRiskCaps = ['Network', 'Process', 'Registry', 'Crypto'];
  if (highRiskCaps.some(capability => capabilities.has(capability))) {
    return 'high';
  }
  if (mediumRiskCaps.some(capability => capabilities.has(capability))) {
    return 'medium';
  }
  return 'low';
}

function riskLabel(level: RiskLevel): string {
  if (level === 'high') {
    return 'High Risk';
  }
  if (level === 'medium') {
    return 'Medium Risk';
  }
  return 'Low Risk';
}

function packingSummary(result: AnalysisResult): string {
  const packing = result.binary.packing;
  const packedBadge = packing?.isPacked ? badge('Packed', 'warn') : badge('Clean', 'success');
  const packers = packing?.packers?.map(packer => `${packer.name}${packer.version ? ` ${packer.version}` : ''}`) ?? [];
  const entropy = packing?.entropy?.overall;
  const suspicious = packing?.suspiciousIndicators ?? [];
  return `
    ${infoRow('Status', packedBadge)}
    ${packers.length > 0 ? infoRow('Packers', escapeHtml(packers.join(', '))) : ''}
    ${infoRow('Overall Entropy', escapeHtml(entropy === undefined ? 'N/A' : entropy.toFixed(2)))}
    ${entropy !== undefined ? bar((entropy / 8) * 100, `${entropy.toFixed(2)} / 8`) : ''}
    ${suspicious.length > 0 ? infoRow('Indicators', escapeHtml(suspicious.join('; '))) : ''}
  `;
}

function renderCapabilities(capabilities: ReturnType<typeof summarizeCapabilities>): string {
  const rows = Array.from(capabilities.names).sort().map(name => `
    <div class="capability-item">
      ${capabilityTag(name as ImportCapability)}
      <span class="capability-count">${escapeHtml(capabilities.counts[name] ?? 0)}</span>
    </div>
  `).join('');

  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">!</span><h2>Detected Capabilities</h2></div>
      <div class="card capability-grid">${rows}</div>
    </div>
  `;
}

function renderSections(sections: SectionInfo[], suspiciousCount: number): string {
  const rows = sections.map(section => [
    code(section.name),
    code(section.start),
    code(section.end),
    escapeHtml(section.size.toLocaleString()),
    code(sectionPermissions(section)),
    `${escapeHtml(section.entropy.toFixed(2))} ${bar((section.entropy / 8) * 100, `${section.entropy.toFixed(2)} / 8`)}`,
    section.anomalies.length > 0
      ? section.anomalies.map(anomaly => badge(anomaly.type, anomaly.severity === 'high' ? 'danger' : anomaly.severity === 'medium' ? 'warn' : 'muted')).join(' ')
      : ''
  ]);
  const contents = table(['Name', 'Start', 'End', 'Size', 'Perms', 'Entropy', 'Anomalies'], rows, {
    id: 'sections-table',
    sortable: true
  });
  return `
    <div class="section">
      <div class="section-header">
        <span class="section-icon">[</span>
        <h2>Sections ${suspiciousCount > 0 ? `<span class="warn">(${escapeHtml(suspiciousCount)} suspicious)</span>` : ''}</h2>
      </div>
      <div class="toolbar">${searchBox('sections-table', 'Search sections')}</div>
      ${contents}
    </div>
  `;
}

function renderFunctions(functions: AnalysisResult['functions']): string {
  const rows = functions.map(func => [
    escapeHtml(func.name),
    code(func.address),
    escapeHtml(func.size.toLocaleString()),
    escapeHtml(func.signature),
    func.isExternal ? badge('external', 'muted') : func.isThunk ? badge('thunk', 'muted') : badge('local', 'accent')
  ]);
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">f</span><h2>Top Functions</h2></div>
      <div class="toolbar">${searchBox('functions-table', 'Search functions')}</div>
      ${table(['Name', 'Address', 'Size', 'Signature', 'Kind'], rows, { id: 'functions-table', sortable: true })}
    </div>
  `;
}

function renderFunctionDetails(result: AnalysisResult, functions: FunctionInfo[], totalLocalFunctions: number): string {
  if (functions.length === 0) {
    return '';
  }

  const lookup = buildFunctionLookup(result.functions);
  const entryPoints = new Set([
    normalizeIdentifier(result.binary.entryPoint),
    normalizeIdentifier(result.entryPoint ?? '')
  ].filter(Boolean));
  const panels = functions.map((func, index) =>
    renderFunctionPanel({
      func,
      result,
      lookup,
      openByDefault: shouldOpenFunctionPanel(func, index, entryPoints)
    })
  ).join('');
  const truncation = totalLocalFunctions > functions.length
    ? `<p class="muted">Showing ${escapeHtml(functions.length)} of ${escapeHtml(totalLocalFunctions)} local functions by size.</p>`
    : '';

  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">d</span><h2>Function Details</h2></div>
      <div class="toolbar">${searchBox('function-details', 'Search function details')}</div>
      ${truncation}
      <div id="function-details" class="function-details">
        ${panels}
      </div>
    </div>
  `;
}

function renderFunctionPanel(input: {
  func: FunctionInfo;
  result: AnalysisResult;
  lookup: Map<string, FunctionInfo>;
  openByDefault: boolean;
}): string {
  const { func, result, lookup, openByDefault } = input;
  const title = [
    escapeHtml(func.name),
    `<span class="muted">${escapeHtml(func.address)}</span>`,
    badge(`${func.size.toLocaleString()} bytes`, 'muted'),
    func.decompileError ? badge('decompile error', 'danger') : '',
    func.pseudocode ? badge('has pseudocode', 'success') : badge('stripped', 'muted')
  ].filter(Boolean).join(' ');
  const stringXrefs = stringsForFunction(result.strings, func);
  const usedImports = importsForFunction(result.imports, func);
  const searchText = [
    func.name,
    func.address,
    func.signature,
    ...func.callers,
    ...func.callees,
    ...stringXrefs.map(stringInfo => stringInfo.value),
    ...usedImports.map(imp => `${imp.name} ${imp.library}`)
  ].join(' ');

  return `
    <details class="collapsible function-detail" id="${escapeHtml(functionAnchor(func.address))}" data-search-item data-search-text="${escapeHtml(searchText)}"${openByDefault ? ' open' : ''}>
      <summary>${title}</summary>
      <div class="collapsible-body">
        ${renderFunctionMetadata(func)}
        <div class="detail-grid">
          ${renderCallList('Callers', func.callers, lookup)}
          ${renderCallList('Callees', func.callees, lookup)}
        </div>
        ${usedImports.length > 0 ? renderFunctionImports(usedImports) : ''}
        ${stringXrefs.length > 0 ? renderFunctionStringXrefs(stringXrefs) : ''}
        ${renderFunctionPseudocode(func)}
        ${renderFunctionHexdump(func)}
        ${renderAgentFunctionAnalysis(func)}
      </div>
    </details>
  `;
}

function renderFunctionMetadata(func: FunctionInfo): string {
  return `
    <div class="function-meta">
      <div class="info-row">
        <span class="info-label">Signature</span>
        <span class="info-value"><span class="mono">${escapeHtml(func.signature)}</span></span>
      </div>
      <div class="info-row">
        <span class="info-label">Address</span>
        <span class="info-value">${code(func.address)}${copyButton(func.address, 'Copy address')}</span>
      </div>
    </div>
  `;
}

function renderCallList(title: string, values: string[], lookup: Map<string, FunctionInfo>): string {
  const items = values.length > 0
    ? values.map(value => `<li>${linkFunctionReference(value, lookup)}</li>`).join('')
    : '<li class="muted">none</li>';
  return `
    <div class="card compact-card">
      <div class="card-title">${escapeHtml(title)}</div>
      <ul class="link-list">${items}</ul>
    </div>
  `;
}

function renderFunctionImports(imports: ImportInfo[]): string {
  const rows = imports.map(imp => [
    escapeHtml(imp.name),
    code(imp.library ?? '-'),
    code(imp.address),
    imp.riskLevel ? badge(imp.riskLevel, imp.riskLevel === 'critical' || imp.riskLevel === 'high' ? 'danger' : imp.riskLevel === 'medium' ? 'warn' : 'success') : '',
    (imp.capabilities ?? []).map(capability => capabilityTag(capability)).join(' ')
  ]);
  return collapsible('Imports Used', table(['Name', 'Library', 'Address', 'Risk', 'Capabilities'], rows, { sortable: true }), true);
}

function renderFunctionStringXrefs(strings: StringInfo[]): string {
  const rows = strings.map(stringInfo => [
    code(stringInfo.address),
    escapeHtml(truncate(stringInfo.value, 180)),
    escapeHtml(stringInfo.encoding),
    escapeHtml(stringInfo.xrefs.length.toLocaleString())
  ]);
  return collapsible('String References', table(['Address', 'Value', 'Encoding', 'Xrefs'], rows, { sortable: true }), true);
}

function renderFunctionPseudocode(func: FunctionInfo): string {
  if (func.pseudocode) {
    const open = func.pseudocode.length < 2500;
    return collapsible('Pseudocode', renderCodeBlock(func.pseudocode, 'code-block'), open);
  }

  if (func.decompileError) {
    return `
      <div class="decompile-error">
        ${badge('decompile error', 'danger')}
        ${collapsible('Decompile Error', renderCodeBlock(func.decompileError, 'code-block error-block'), true)}
      </div>
    `;
  }

  return '<p class="muted">no decompilation available</p>';
}

function renderFunctionHexdump(func: FunctionInfo): string {
  if (!func.hexdump) {
    return '';
  }
  const heading = `Hexdump at ${func.hexdump.address}`;
  return collapsible(heading, renderCodeBlock(func.hexdump.formatted, 'hexdump-block'), false);
}

function renderAgentFunctionAnalysis(func: FunctionInfo): string {
  if (!func.agentAnalysis) {
    return '';
  }
  const analysis = func.agentAnalysis;
  const body = `
    ${infoRow('Semantic Name', escapeHtml(analysis.semanticName))}
    ${infoRow('Confidence', escapeHtml(`${Math.round(analysis.confidence * 100)}%`))}
    <div class="analysis-note"><strong>Purpose</strong><p>${escapeHtml(analysis.purpose)}</p></div>
    <div class="analysis-note"><strong>Security Notes</strong><p>${escapeHtml(analysis.securityNotes)}</p></div>
  `;
  return collapsible('Agent Analysis', body, false);
}

function buildFunctionLookup(functions: FunctionInfo[]): Map<string, FunctionInfo> {
  const lookup = new Map<string, FunctionInfo>();
  for (const func of functions) {
    for (const value of [func.name, func.address]) {
      const normalized = normalizeIdentifier(value);
      if (normalized) {
        lookup.set(normalized, func);
      }
    }
  }
  return lookup;
}

function shouldOpenFunctionPanel(func: FunctionInfo, index: number, entryPoints: Set<string>): boolean {
  const name = normalizeIdentifier(func.name);
  const address = normalizeIdentifier(func.address);
  return name === 'main' || entryPoints.has(address) || index < 3;
}

function linkFunctionReference(value: string, lookup: Map<string, FunctionInfo>): string {
  const target = lookup.get(normalizeIdentifier(value));
  if (!target) {
    return `<span class="mono">${escapeHtml(value)}</span>`;
  }
  return `<a class="mono" href="#${escapeHtml(functionAnchor(target.address))}">${escapeHtml(value)}</a>`;
}

function stringsForFunction(strings: StringInfo[], func: FunctionInfo): StringInfo[] {
  return strings.filter(stringInfo => stringInfo.xrefs.some(xref => functionMatchesXref(func, xref.function) || functionMatchesXref(func, xref.address)));
}

function functionMatchesXref(func: FunctionInfo, value: string): boolean {
  const normalized = normalizeIdentifier(value);
  return normalized === normalizeIdentifier(func.address) || normalized === normalizeIdentifier(func.name);
}

function importsForFunction(imports: ImportInfo[], func: FunctionInfo): ImportInfo[] {
  const callees = new Set(func.callees.map(normalizeIdentifier).filter(Boolean));
  const seen = new Set<string>();
  return imports.filter(imp => {
    const matches = callees.has(normalizeIdentifier(imp.name)) || callees.has(normalizeIdentifier(imp.address));
    const key = `${imp.name}:${imp.library}:${imp.address}`;
    if (!matches || seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function renderCodeBlock(value: string, className: string): string {
  return `<pre class="${escapeHtml(className)}"><code>${escapeHtml(value)}</code></pre>`;
}

function functionAnchor(address: string): string {
  return `fn-${sanitizeAnchorId(address)}`;
}

function sanitizeAnchorId(value: string): string {
  const sanitized = value.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  return sanitized || 'unknown';
}

function normalizeIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

function renderStrings(strings: StringInfo[]): string {
  const rows = strings.map(stringInfo => {
    const value = escapeHtml(truncate(stringInfo.value, 180));
    const copy = isFlagLike(stringInfo.value) ? copyButton(stringInfo.value, 'Copy string') : '';
    return [
      code(stringInfo.address),
      `${value}${copy}`,
      escapeHtml(stringInfo.length.toLocaleString()),
      escapeHtml(stringInfo.encoding),
      escapeHtml(stringInfo.section ?? ''),
      escapeHtml(stringInfo.xrefs.length.toLocaleString())
    ];
  });
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">"</span><h2>Interesting Strings</h2></div>
      <div class="toolbar">${searchBox('strings-table', 'Search strings')}</div>
      ${table(['Address', 'Value', 'Length', 'Encoding', 'Section', 'Xrefs'], rows, { id: 'strings-table', sortable: true })}
    </div>
  `;
}

function renderImports(result: AnalysisResult): string {
  const rows = result.imports.slice(0, 250).map(imp => [
    escapeHtml(imp.name),
    code(imp.library ?? '-'),
    code(imp.address),
    imp.riskLevel ? badge(imp.riskLevel, imp.riskLevel === 'critical' || imp.riskLevel === 'high' ? 'danger' : imp.riskLevel === 'medium' ? 'warn' : 'success') : '',
    (imp.capabilities ?? []).map(capability => capabilityTag(capability)).join(' ')
  ]);
  const overflow = result.imports.length > 250
    ? `<p class="muted">Showing 250 of ${escapeHtml(result.imports.length)} imports.</p>`
    : '';
  const contents = `
    <div class="toolbar">${searchBox('imports-table', 'Search imports')}</div>
    ${table(['Function', 'Library', 'Address', 'Risk', 'Capabilities'], rows, { id: 'imports-table', sortable: true })}
    ${overflow}
  `;
  return `
    <div class="section">
      <div class="section-header"><span class="section-icon">&lt;</span><h2>Imports</h2></div>
      ${result.imports.length > 100 ? collapsible('Imports table', contents, true) : contents}
    </div>
  `;
}

function capabilityTag(capability: ImportCapability | string): string {
  const dangerous = new Set(['Injection', 'AntiDebug', 'Persistence']);
  const warning = new Set(['Network', 'Process', 'Registry', 'Crypto']);
  const kind = dangerous.has(capability)
    ? 'tag-danger'
    : warning.has(capability)
      ? 'tag-warn'
      : 'tag-success';
  return `<span class="tag ${kind}">${escapeHtml(capability)}</span>`;
}

function hashRow(label: string, value: string): string {
  return infoRow(label, `<span class="hash-value">${escapeHtml(value)}</span>${copyButton(value, `Copy ${label}`)}`);
}

function infoRow(label: string, valueHtml: string): string {
  return `<div class="info-row"><span class="info-label">${escapeHtml(label)}</span><span class="info-value">${valueHtml}</span></div>`;
}

function code(value: unknown): string {
  return `<code>${escapeHtml(value ?? '-')}</code>`;
}

function sectionPermissions(section: SectionInfo): string {
  return `${section.permissions.read ? 'r' : '-'}${section.permissions.write ? 'w' : '-'}${section.permissions.execute ? 'x' : '-'}`;
}

function isSuspiciousSection(section: SectionInfo): boolean {
  return section.entropy > 7.0 || (section.permissions.write && section.permissions.execute);
}

function isInterestingString(stringInfo: StringInfo): boolean {
  const value = stringInfo.value.toLowerCase();
  return value.includes('flag') ||
    value.includes('password') ||
    value.includes('key') ||
    value.includes('secret') ||
    value.includes('http') ||
    value.includes('error') ||
    value.includes('api') ||
    value.includes('token') ||
    value.includes('credential') ||
    /^[A-Z]{2,}[{_]/.test(stringInfo.value) ||
    /\d{1,3}(?:\.\d{1,3}){3}/.test(stringInfo.value);
}

function isFlagLike(value: string): boolean {
  return /[A-Za-z0-9_.+-]+@flare-on\.com/.test(value) || /\b[A-Za-z0-9_]{2,}\{[^}\n]{1,256}\}/.test(value);
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`;
  }
  return `${bytes.toLocaleString()} bytes`;
}
