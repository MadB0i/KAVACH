import type { ReactNode } from 'react';
import EmptyState from './EmptyState';

interface Column<T> {
  key: string;
  header: string;
  render: (row: T, index: number) => ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyField: (row: T, index: number) => string | number;
  emptyIcon?: string;
  emptyTitle?: string;
  emptyDescription?: string;
  compact?: boolean;
  rowLabel?: (row: T) => string;
}

export default function DataTable<T>({
  columns,
  data,
  keyField,
  emptyIcon = '\u25A1',
  emptyTitle = 'No Data',
  emptyDescription = 'There are no records to display.',
  compact = false,
  rowLabel,
}: DataTableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="table-wrapper">
        <EmptyState icon={emptyIcon} title={emptyTitle} description={emptyDescription} />
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table className={`table ${compact ? 'table--sm' : ''}`} role="table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} className={col.className}>{col.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => (
            <tr key={keyField(row, idx)} aria-label={rowLabel?.(row)}>
              {columns.map((col) => (
                <td key={col.key} className={col.className} data-label={col.header}>{col.render(row, idx)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
