import type { ScanResult } from '../../types/scan';

function _progressLabel(done: number, total: number) {
  if (total <= 0) return '0/0';
  return `${done}/${total}`;
}

export function ScanProgress({
  results,
  isScanning,
  startedAt
}: {
  results: ScanResult[];
  isScanning: boolean;
  startedAt?: Date;
}) {
  const total = results.length;
  const completed = results.filter(r => r.status === 'completed').length;
  const failed = results.filter(r => r.status === 'failed').length;
  const timeouts = results.filter(r => r.status === 'timeout').length;

  const done = completed + failed + timeouts;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  const elapsed = startedAt ? Math.max(0, Date.now() - startedAt.getTime()) : 0;
  const elapsedS = Math.round(elapsed / 1000);

  return (
    <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[#c9d1d9] font-semibold">Progression du scan</div>
          <div className="text-xs text-[#7d8590] mt-1">
            {isScanning ? 'Scan en cours…' : 'Dernier état du scan'} — {_progressLabel(done, total)} modules — {pct}%
            {startedAt ? ` — ${elapsedS}s` : ''}
          </div>
        </div>
        <div className="text-xs text-[#7d8590] text-right">
          <div><span className="text-[#3fb950]">✓</span> {completed}</div>
          <div><span className="text-[#ff9500]">⏱</span> {timeouts}</div>
          <div><span className="text-[#f85149]">✗</span> {failed}</div>
        </div>
      </div>

      <div className="mt-3 h-2 w-full rounded bg-[#0d1117] border border-[#30363d] overflow-hidden">
        <div
          className="h-full bg-[#1f6feb]"
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2">
        {results.map(r => (
          <div key={r.moduleId} className="flex items-center justify-between gap-3">
            <div className="text-xs text-[#c9d1d9] truncate">{r.moduleName}</div>
            <div className="text-xs">
              {r.status === 'completed' && (<span className="text-[#3fb950]">✓ Success</span>)}
              {r.status === 'timeout' && (<span className="text-[#ff9500]">⏱ Timeout</span>)}
              {r.status === 'failed' && (<span className="text-[#f85149]">⚠ Technical Error</span>)}
              {r.status === 'started' && (<span className="text-[#58a6ff]">… Running</span>)}
              {(r.status === 'pending' || r.status === 'running') && (<span className="text-[#58a6ff]">… Running</span>)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
