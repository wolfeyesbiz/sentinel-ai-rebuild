import React, { useState, useEffect } from 'react';
import { X, Lock, Unlock, ShieldAlert, Plus, ShieldCheck } from 'lucide-react';
import { BlockedIPItem, WafRule } from '../types';
import { apiFetch, apiUrl } from '../api';

interface FirewallModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRefresh: () => void;
}

export const FirewallModal: React.FC<FirewallModalProps> = ({
  isOpen,
  onClose,
  onRefresh
}) => {
  const [activeTab, setActiveTab] = useState<'blocked' | 'waf'>('blocked');
  const [blockedList, setBlockedList] = useState<BlockedIPItem[]>([]);
  const [wafRules, setWafRules] = useState<WafRule[]>([]);
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('');
  const [durationHours, setDurationHours] = useState(24);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadData();
    }
  }, [isOpen]);

  const loadData = async () => {
    try {
      const ipRes = await apiFetch(apiUrl('/api/security/blocked-ips'));
      const ipData = await ipRes.json();
      setBlockedList(ipData);

      const wafRes = await apiFetch(apiUrl('/api/security/rules'));
      const wafData = await wafRes.json();
      setWafRules(wafData);
    } catch (e) {
      console.error('Failed to load firewall data', e);
    }
  };

  const handleManualBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIP) return;
    setIsLoading(true);
    try {
      await apiFetch(apiUrl('/api/security/block-ip'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_address: newIP.trim(),
          duration_hours: durationHours,
          reason: newReason.trim() || 'Manual administrative ban'
        })
      });
      setNewIP('');
      setNewReason('');
      await loadData();
      onRefresh();
    } catch (e) {
      console.error('Failed to block IP', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      await apiFetch(apiUrl('/api/security/unblock-ip'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip_address: ip })
      });
      await loadData();
      onRefresh();
    } catch (e) {
      console.error('Failed to unblock IP', e);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-[var(--color-paper-2)] border border-[var(--color-rule)] w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="bg-[var(--color-sidebar)] border-b border-[var(--color-rule)] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-amber-500/15 border border-amber-500/30 text-amber-400">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-mono text-white">
                SENTINEL AI · FIREWALL & WAF RULES MANAGER
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Manage dynamic IP jail, blacklist, and edge WAF inspection patterns
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

        {/* Tab Selector */}
        <div className="flex border-b border-[var(--color-rule)] bg-[var(--color-paper-3)] px-6 pt-2 gap-4">
          <button
            onClick={() => setActiveTab('blocked')}
            className={`pb-2.5 text-xs font-mono font-bold border-b-2 transition-all cursor-pointer ${
              activeTab === 'blocked'
                ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Active Blocked IPs ({blockedList.length})
          </button>
          <button
            onClick={() => setActiveTab('waf')}
            className={`pb-2.5 text-xs font-mono font-bold border-b-2 transition-all cursor-pointer ${
              activeTab === 'waf'
                ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            WAF Rules & Inspection Engine ({wafRules.length})
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {activeTab === 'blocked' ? (
            <>
              {/* Form to manually block IP */}
              <form onSubmit={handleManualBlock} className="bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded-lg p-4 font-mono text-xs">
                <h4 className="font-bold text-white mb-3 flex items-center gap-1.5">
                  <Plus className="w-4 h-4 text-[var(--color-accent)]" />
                  MANUALLY QUARANTINE IP ADDRESS
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
                  <div>
                    <label className="text-slate-400 block mb-1">IP Address / CIDR:</label>
                    <input
                      type="text"
                      placeholder="e.g. 198.51.100.99"
                      value={newIP}
                      onChange={e => setNewIP(e.target.value)}
                      required
                      className="w-full bg-[var(--color-paper-2)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-white focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Reason:</label>
                    <input
                      type="text"
                      placeholder="e.g. SQLi / Suspicious probing"
                      value={newReason}
                      onChange={e => setNewReason(e.target.value)}
                      className="w-full bg-[var(--color-paper-2)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-white focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Ban Duration (Hours):</label>
                    <select
                      value={durationHours}
                      onChange={e => setDurationHours(Number(e.target.value))}
                      className="w-full bg-[var(--color-paper-2)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-white focus:outline-none focus:border-[var(--color-accent)]"
                    >
                      <option value={1}>1 Hour</option>
                      <option value={12}>12 Hours</option>
                      <option value={24}>24 Hours (Default)</option>
                      <option value={168}>7 Days</option>
                      <option value={0}>Permanent Ban</option>
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="px-4 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white font-bold transition-all cursor-pointer"
                >
                  {isLoading ? 'Blocking...' : 'Enforce Immediate Block'}
                </button>
              </form>

              {/* Blocked List Table */}
              <div className="border border-[var(--color-rule)] rounded-lg overflow-hidden bg-[var(--color-paper-3)]">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[var(--color-rule)] text-slate-400 bg-[var(--color-sidebar)]">
                      <th className="py-2.5 px-3">IP ADDRESS</th>
                      <th className="py-2.5 px-3">REASON</th>
                      <th className="py-2.5 px-3">BLOCKED AT</th>
                      <th className="py-2.5 px-3">STATUS</th>
                      <th className="py-2.5 px-3 text-right">ACTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-rule)]/40">
                    {blockedList.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-6 text-center text-slate-400">
                          No IPs currently in quarantine jail.
                        </td>
                      </tr>
                    ) : (
                      blockedList.map(item => (
                        <tr key={item.ip_address} className="hover:bg-[var(--color-accent-soft)]">
                          <td className="py-2.5 px-3 font-bold text-[var(--color-bad)]">
                            {item.ip_address}
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">
                            {item.reason}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400">
                            {new Date(item.blocked_at).toLocaleTimeString()}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 text-[10px]">
                              {item.permanent ? 'PERMANENT' : 'TEMPORARY'}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={() => handleUnblock(item.ip_address)}
                              className="px-2.5 py-1 rounded bg-[var(--color-accent-soft)] hover:bg-emerald-600 hover:text-white text-emerald-400 border border-emerald-500/30 font-semibold cursor-pointer transition-all"
                            >
                              Unblock
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            /* WAF Rules Tab */
            <div className="space-y-3 font-mono text-xs">
              {wafRules.map(rule => (
                <div key={rule.id} className="bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white text-sm">{rule.name}</span>
                      <span className="px-1.5 py-0.5 rounded bg-[var(--color-accent)]/10 text-[var(--color-accent)] border border-[var(--color-accent)]/30 text-[10px]">
                        {rule.threat_type}
                      </span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                      ACTIVE (ENFORCED)
                    </span>
                  </div>

                  <p className="text-slate-400 text-xs mb-2 font-sans">{rule.description}</p>

                  <div className="bg-black/80 rounded p-2 text-emerald-400 border border-[var(--color-rule)] break-all">
                    <code>Pattern: {rule.pattern}</code>
                  </div>
                </div>
              ))}
            </div>
          )}
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
