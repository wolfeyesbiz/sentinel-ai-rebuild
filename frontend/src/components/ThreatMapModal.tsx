import React from 'react';
import { X, Globe, Shield, MapPin, Compass } from 'lucide-react';
import { AlertItem } from '../types';

interface ThreatMapModalProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: AlertItem[];
}

export const ThreatMapModal: React.FC<ThreatMapModalProps> = ({
  isOpen,
  onClose,
  alerts
}) => {
  if (!isOpen) return null;

  // Aggregate country statistics
  const countryCounts: Record<string, { count: number; threats: Set<string> }> = {};
  alerts.forEach(a => {
    const c = a.country || 'Unknown';
    if (!countryCounts[c]) {
      countryCounts[c] = { count: 0, threats: new Set() };
    }
    countryCounts[c].count += 1;
    countryCounts[c].threats.add(a.threat_type);
  });

  const sortedCountries = Object.entries(countryCounts).sort((a, b) => b[1].count - a[1].count);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-[var(--color-paper-2)] border border-[var(--color-rule)] w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="bg-[var(--color-sidebar)] border-b border-[var(--color-rule)] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/30 text-[var(--color-accent)]">
              <Globe className="w-6 h-6 animate-spin-slow" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-mono text-white">
                SENTINEL AI · GLOBAL THREAT RADAR
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Geographic attack origin visualization & telemetry mapping
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[var(--color-rule)]/50 transition-all cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Radar Visualizer Card matching Slide 1 & Slide 10 */}
          <div className="relative h-72 rounded-xl bg-gradient-to-b from-[var(--color-paper-3)] to-[var(--color-paper-2)] border border-[var(--color-rule)] flex items-center justify-center overflow-hidden">
            {/* Concentric Radar Rings */}
            <div className="absolute w-64 h-64 rounded-full border border-[var(--color-accent)]/20" />
            <div className="absolute w-48 h-48 rounded-full border border-[var(--color-accent)]/30" />
            <div className="absolute w-32 h-32 rounded-full border border-[var(--color-accent)]/40" />
            <div className="absolute w-16 h-16 rounded-full border border-[var(--color-accent)]/50" />

            {/* Radar Crosshairs */}
            <div className="absolute w-full h-[1px] bg-[var(--color-accent)]/20" />
            <div className="absolute h-full w-[1px] bg-[var(--color-accent)]/20" />

            {/* Rotating Radar Sweep Needle */}
            <div
              className="absolute w-64 h-64 rounded-full origin-center animate-spin"
              style={{
                background: 'conic-gradient(from 0deg, color-mix(in oklab, var(--color-accent) 40%, transparent) 0deg, transparent 60deg, transparent 360deg)',
                animationDuration: '6s'
              }}
            />

            {/* Simulated Live Geographic Hotspot Nodes */}
            <div className="absolute top-1/4 left-1/3 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[var(--color-bad)] animate-ping" />
              <span className="text-[10px] font-mono font-bold text-[var(--color-bad)] bg-black/80 px-1 rounded border border-red-900">
                Russia (SQLi)
              </span>
            </div>

            <div className="absolute bottom-1/3 right-1/4 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[var(--color-warn)] animate-ping" />
              <span className="text-[10px] font-mono font-bold text-[var(--color-warn)] bg-black/80 px-1 rounded border border-amber-900">
                China (Brute Force)
              </span>
            </div>

            <div className="absolute top-1/2 right-1/3 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[var(--color-accent)] animate-pulse" />
              <span className="text-[10px] font-mono font-bold text-[var(--color-accent)] bg-black/80 px-1 rounded border border-cyan-900">
                Germany (Bot Scraping)
              </span>
            </div>

            <div className="absolute bottom-1/4 left-1/4 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-purple-500 animate-ping" />
              <span className="text-[10px] font-mono font-bold text-purple-400 bg-black/80 px-1 rounded border border-purple-900">
                Vietnam (Session Jump)
              </span>
            </div>

            {/* Center Shield Icon */}
            <div className="z-10 p-3 rounded-full bg-[var(--color-accent-soft)] border border-[var(--color-accent)]  text-[var(--color-accent)]">
              <Shield className="w-7 h-7" />
            </div>
          </div>

          {/* Country breakdown list */}
          <div>
            <h4 className="text-xs font-mono font-bold tracking-widest text-[var(--color-accent)] uppercase mb-3 flex items-center gap-1.5">
              <MapPin className="w-4 h-4" />
              ATTACK ORIGINS & GEOGRAPHIC DISTRIBUTION
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {sortedCountries.length === 0 ? (
                <div className="col-span-3 text-center py-6 text-slate-400 text-xs font-mono">
                  No attack telemetry recorded yet.
                </div>
              ) : (
                sortedCountries.map(([country, data]) => (
                  <div key={country} className="bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded-lg p-3 text-xs font-mono">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-white font-bold">{country}</span>
                      <span className="px-1.5 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800 text-[10px]">
                        {data.count} attacks
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      Vectors: {Array.from(data.threats).join(', ') || 'N/A'}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-[var(--color-sidebar)] border-t border-[var(--color-rule)] px-6 py-3 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded bg-[var(--color-paper-2)] hover:bg-[var(--color-rule)] text-slate-300 border border-[var(--color-rule)] font-mono text-xs cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
