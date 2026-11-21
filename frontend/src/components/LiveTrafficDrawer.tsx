import React from 'react';
import { X, Activity, Radio, ArrowDown } from 'lucide-react';
import { TrafficPacket } from '../types';

interface LiveTrafficDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  packets: TrafficPacket[];
}

export const LiveTrafficDrawer: React.FC<LiveTrafficDrawerProps> = ({
  isOpen,
  onClose,
  packets
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] bg-[var(--color-paper-2)] border-l border-[var(--color-rule)] shadow-2xl flex flex-col">
      {/* Header */}
      <div className="bg-[var(--color-sidebar)] border-b border-[var(--color-rule)] px-5 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Activity className="w-5 h-5 text-[var(--color-accent)] animate-pulse" />
          <div>
            <h3 className="font-mono font-bold text-sm text-white">LIVE TRAFFIC INSPECTOR</h3>
            <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              Real-time Ingress Stream
            </span>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1 rounded text-slate-400 hover:text-white hover:bg-[var(--color-rule)] transition-all cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Stream List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-xs">
        {packets.length === 0 ? (
          <div className="text-center py-12 text-slate-400">Waiting for live packets...</div>
        ) : (
          packets.map((pkt, idx) => {
            const isBlocked = pkt.status === 403 || pkt.action === 'blocked';
            return (
              <div
                key={pkt.id || idx}
                className={`p-2.5 rounded border transition-all ${
                  isBlocked
                    ? 'bg-red-950/40 border-red-800 text-red-200'
                    : 'bg-[var(--color-paper-3)] border-[var(--color-rule)] text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold text-slate-400">{pkt.timestamp}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                      pkt.method === 'POST' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-blue-950 text-blue-300 border border-blue-800'
                    }`}>
                      {pkt.method}
                    </span>
                    <span className="font-semibold text-white">{pkt.ip}</span>
                  </div>

                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                    isBlocked
                      ? 'bg-red-600 text-white'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {pkt.status} {pkt.action.toUpperCase()}
                  </span>
                </div>

                <div className="text-[11px] text-[var(--color-accent)] truncate mb-1" title={pkt.path}>
                  {pkt.path}
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>{pkt.country}</span>
                  <span>Risk Score: {pkt.risk_score}</span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Footer */}
      <div className="bg-[var(--color-sidebar)] border-t border-[var(--color-rule)] p-3 text-center text-xs font-mono text-slate-400">
        Sliding buffer: last {packets.length} packets
      </div>
    </div>
  );
};
