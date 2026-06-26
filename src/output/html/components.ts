import { escapeHtml } from './escape';

export type BadgeKind = 'success' | 'warn' | 'danger' | 'muted' | 'accent';

export interface TableOptions {
  id?: string;
  className?: string;
  sortable?: boolean;
}

export interface TableRow {
  cells: string[];
  attrs?: Record<string, string | number | boolean | null | undefined>;
}

export function statCard(label: string, value: string | number, detail?: string): string {
  return `
    <div class="card stat-card">
      <div class="card-title">${escapeHtml(label)}</div>
      <div class="card-value">${escapeHtml(value)}</div>
      ${detail ? `<div class="card-label">${escapeHtml(detail)}</div>` : ''}
    </div>
  `;
}

export function badge(text: string, kind: BadgeKind = 'muted'): string {
  return `<span class="badge badge-${kind}">${escapeHtml(text)}</span>`;
}

export function bar(valuePct: number | null | undefined, label?: string): string {
  const safeValue = Number.isFinite(valuePct ?? NaN)
    ? Math.max(0, Math.min(100, valuePct ?? 0))
    : 0;
  const text = label ?? `${safeValue.toFixed(0)}%`;
  return `
    <span class="bar" title="${escapeHtml(text)}">
      <span class="bar-fill" style="width: ${safeValue.toFixed(2)}%"></span>
      <span class="bar-label">${escapeHtml(text)}</span>
    </span>
  `;
}

export function copyButton(text: string | null | undefined, label = 'Copy'): string {
  const value = text ?? '';
  return `<button type="button" class="icon-button copy-button" data-copy="${escapeHtml(value)}" title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}">Copy</button>`;
}

export function searchBox(targetTableId: string, placeholder = 'Search'): string {
  return `
    <label class="search-box">
      <span class="sr-only">${escapeHtml(placeholder)}</span>
      <input type="search" data-search-target="${escapeHtml(targetTableId)}" placeholder="${escapeHtml(placeholder)}">
    </label>
  `;
}

export function solvedOnlyToggle(targetTableId: string): string {
  return `
    <label class="toggle">
      <input type="checkbox" data-solved-toggle="${escapeHtml(targetTableId)}">
      <span>Solved only</span>
    </label>
  `;
}

export function collapsible(title: string, innerHtml: string, openByDefault = false): string {
  return `
    <details class="collapsible"${openByDefault ? ' open' : ''}>
      <summary>${escapeHtml(title)}</summary>
      <div class="collapsible-body">${innerHtml}</div>
    </details>
  `;
}

export function table(headers: string[], rows: Array<string[] | TableRow>, options: TableOptions = {}): string {
  const attrs = [
    options.id ? `id="${escapeHtml(options.id)}"` : '',
    options.className ? `class="${escapeHtml(options.className)}"` : ''
  ].filter(Boolean).join(' ');

  return `
    <div class="table-wrapper">
      <table ${attrs}>
        <thead>
          <tr>
            ${headers.map(header => `<th${options.sortable ? ' data-sortable="true"' : ''}>${escapeHtml(header)}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
          ${rows.map(row => {
            const cells = Array.isArray(row) ? row : row.cells;
            const rowAttrs = Array.isArray(row) ? '' : attrsFromRecord(row.attrs);
            return `<tr${rowAttrs}>${cells.map(cell => `<td>${cell}</td>`).join('')}</tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function attrsFromRecord(attrs: TableRow['attrs']): string {
  if (!attrs) {
    return '';
  }
  const rendered = Object.entries(attrs)
    .filter((entry): entry is [string, string | number | boolean] => entry[1] !== null && entry[1] !== undefined)
    .map(([key, value]) => `${escapeHtml(key)}="${escapeHtml(value)}"`);
  return rendered.length > 0 ? ` ${rendered.join(' ')}` : '';
}
