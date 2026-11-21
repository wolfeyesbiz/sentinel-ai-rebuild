import React, { useState } from 'react';
import { AlertItem } from '../types';
import { X, ShieldAlert, CheckCircle2, Copy, Check, Lock, Unlock, AlertTriangle, Terminal, Code2 } from 'lucide-react';

interface ThreatDetailModalProps {
  alert: AlertItem | null;
  onClose: () => void;
  onBlockIP: (ip: string, reason: string) => Promise<void>;
  onUnblockIP: (ip: string) => Promise<void>;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  alert,
  onClose,
  onBlockIP,
  onUnblockIP
}) => {
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [isBlocking, setIsBlocking] = useState(false);
  const [isUnblocking, setIsUnblocking] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  if (!alert) return null;

  const remediation = alert.remediation;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const handlePermanentBlock = async () => {
    setIsBlocking(true);
    try {
      await onBlockIP(alert.source_ip, `Permanent manual block for ${alert.threat_type}`);
      setActionMessage(`IP ${alert.source_ip} permanently blocked.`);
    } catch {
      setActionMessage('Failed to block IP.');
    } finally {
      setIsBlocking(false);
    }
  };

  const handleUnblock = async () => {
    setIsUnblocking(true);
    try {
      await onUnblockIP(alert.source_ip);
      setActionMessage(`IP ${alert.source_ip} unblocked.`);
    } catch {
      setActionMessage('Failed to unblock IP.');
    } finally {
      setIsUnblocking(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-[var(--color-paper-2)] border border-[var(--color-rule)] w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Top Header */}
        <div className="bg-[var(--color-sidebar)] border-b border-[var(--color-rule)] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-[var(--color-bad)]/15 border border-[var(--color-bad)]/30 text-[var(--color-bad)]">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[var(--color-bad)]/20 text-[var(--color-bad)] border border-[var(--color-bad)]/40">
                  {alert.severity.toUpperCase()} THREAT DETECTED
                </span>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                  Status: {alert.status.toUpperCase()} ✓
                </span>
              </div>
              <h2 className="text-xl font-bold font-mono text-white mt-0.5">
                {alert.threat_type.replace('_', ' ').toUpperCase()} ATTEMPT
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[var(--color-rule)]/50 transition-all cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {actionMessage && (
          <div className="bg-[var(--color-accent)]/15 border-b border-[var(--color-accent)]/30 px-6 py-2 text-xs font-mono text-[var(--color-accent)] flex items-center justify-between">
            <span>{actionMessage}</span>
            <button onClick={() => setActionMessage(null)} className="underline cursor-pointer">dismiss</button>
          </div>
        )}

        {/* Modal Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm font-sans text-slate-200">
          {/* SECTION 1: ATTACK DETAILS */}
          <div className="border border-[var(--color-rule)] rounded-lg p-4 bg-[var(--color-paper-3)]/80">
            <h4 className="text-xs font-mono font-bold tracking-widest text-[var(--color-accent)] uppercase mb-3 flex items-center gap-1.5">
              <Terminal className="w-4 h-4" />
              ATTACK DETAILS
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-400 block">Source IP:</span>
                <span className="text-white font-semibold text-sm">
                  {alert.source_ip} <span className="text-slate-400 font-normal">({alert.country})</span>
                </span>
              </div>
              <div>
                <span className="text-slate-400 block">Target:</span>
                <span className="text-[var(--color-accent)] break-all">{alert.target}</span>
              </div>
              <div>
                <span className="text-slate-400 block">Attack Vector:</span>
                <span className="text-slate-300">{alert.attack_vector || 'HTTP Request Parameter / Body Injection'}</span>
              </div>
              <div>
                <span className="text-slate-400 block">Risk Score:</span>
                <span className="text-lg font-bold text-[var(--color-bad)]">{alert.risk_score.toFixed(2)} / 1.0</span>
              </div>
            </div>

            {/* Malicious Payload Box */}
            {alert.payload && (
              <div className="mt-3">
                <span className="text-xs font-mono text-slate-400 block mb-1">Malicious Payload:</span>
                <div className="bg-black/80 rounded p-2.5 font-mono text-xs text-red-400 border border-red-950 flex items-center justify-between break-all">
                  <code>{alert.payload}</code>
                  <button
                    onClick={() => handleCopy(alert.payload || '', 'payload')}
                    className="ml-2 p-1 text-slate-400 hover:text-white"
                    title="Copy payload"
                  >
                    {copiedCode === 'payload' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* SECTION 2: IMPACT ASSESSMENT */}
          {remediation && (
            <div className="border border-[var(--color-rule)] rounded-lg p-4 bg-[var(--color-paper-3)]/80">
              <h4 className="text-xs font-mono font-bold tracking-widest text-amber-400 uppercase mb-3 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" />
                IMPACT ASSESSMENT
              </h4>
              <div className="space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-400">Potential Damage: </span>
                  <span className="text-[var(--color-bad)] font-semibold">{remediation.impact_assessment.potential_damage}</span>
                </div>
                <div>
                  <span className="text-slate-400">Data at Risk: </span>
                  <span className="text-white">{remediation.impact_assessment.data_at_risk}</span>
                </div>
                <div>
                  <span className="text-slate-400">Business Impact: </span>
                  <span className="text-slate-300">{remediation.impact_assessment.business_impact}</span>
                </div>
              </div>
            </div>
          )}

          {/* SECTION 3: IMMEDIATE ACTIONS TAKEN BY SENTINEL AI */}
          <div className="border border-[var(--color-ok)]/30 rounded-lg p-4 bg-[var(--color-ok)]/5">
            <h4 className="text-xs font-mono font-bold tracking-widest text-[var(--color-ok)] uppercase mb-3 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              IMMEDIATE ACTIONS TAKEN BY SENTINEL AI
            </h4>
            <ul className="space-y-1.5 text-xs font-mono text-slate-300">
              {remediation?.immediate_actions_taken.map((action, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-[var(--color-ok)] font-bold">✓</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* SECTION 4: HOW TO FIX THIS NOW */}
          <div className="border border-[var(--color-rule)] rounded-lg p-4 bg-[var(--color-paper-3)]/80">
            <h4 className="text-xs font-mono font-bold tracking-widest text-cyan-300 uppercase mb-3 flex items-center gap-1.5">
              <span>🔧</span>
              HOW TO FIX THIS NOW
            </h4>
            <div className="space-y-3 text-xs font-mono">
              {remediation?.how_to_fix_now.map((step, idx) => (
                <div key={idx} className="bg-[var(--color-paper-2)] p-3 rounded border border-[var(--color-rule)]">
                  <p className="text-slate-200">{step}</p>
                </div>
              ))}
            </div>
          </div>

          {/* SECTION 5: HOW TO PREVENT THIS IN THE FUTURE */}
          <div className="border border-[var(--color-rule)] rounded-lg p-4 bg-[var(--color-paper-3)]/80">
            <h4 className="text-xs font-mono font-bold tracking-widest text-[var(--color-accent)] uppercase mb-3 flex items-center gap-1.5">
              <Code2 className="w-4 h-4" />
              🛡️ HOW TO PREVENT THIS IN THE FUTURE (CODE & CONFIG)
            </h4>
            <div className="space-y-4">
              {remediation?.prevention_measures.map((measure, idx) => (
                <div key={idx} className="bg-[var(--color-paper-2)] rounded-lg p-4 border border-[var(--color-rule)]">
                  <div className="flex items-center justify-between mb-1.5">
                    <h5 className="text-xs font-mono font-bold text-white">
                      {idx + 1}. {measure.title}
                    </h5>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--color-sidebar)] text-cyan-400 border border-[var(--color-rule)] uppercase">
                      {measure.priority}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mb-3 font-sans">
                    {measure.description}
                  </p>

                  {/* Code snippet if present */}
                  {measure.code_example && (
                    <div className="relative mb-2">
                      <div className="flex items-center justify-between bg-[var(--color-paper-3)] px-3 py-1.5 rounded-t text-[11px] font-mono text-slate-400 border-x border-t border-[var(--color-rule)]">
                        <span>Code Implementation Fix</span>
                        <button
                          onClick={() => handleCopy(measure.code_example || '', `code_${idx}`)}
                          className="flex items-center gap-1 text-xs hover:text-white"
                        >
                          {copiedCode === `code_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{copiedCode === `code_${idx}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="bg-black/90 p-3 rounded-b overflow-x-auto text-xs font-mono text-emerald-400 border border-[var(--color-rule)]">
                        <code>{measure.code_example}</code>
                      </pre>
                    </div>
                  )}

                  {/* Configuration directive if present */}
                  {measure.configuration && (
                    <div className="relative">
                      <div className="flex items-center justify-between bg-[var(--color-paper-3)] px-3 py-1.5 rounded-t text-[11px] font-mono text-slate-400 border-x border-t border-[var(--color-rule)]">
                        <span>WAF / Reverse Proxy Configuration Directive</span>
                        <button
                          onClick={() => handleCopy(measure.configuration || '', `conf_${idx}`)}
                          className="flex items-center gap-1 text-xs hover:text-white"
                        >
                          {copiedCode === `conf_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{copiedCode === `conf_${idx}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="bg-black/90 p-3 rounded-b overflow-x-auto text-xs font-mono text-amber-300 border border-[var(--color-rule)]">
                        <code>{measure.configuration}</code>
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Modal Bottom Actions */}
        <div className="bg-[var(--color-sidebar)] border-t border-[var(--color-rule)] px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <button
              onClick={handlePermanentBlock}
              disabled={isBlocking}
              className="flex items-center gap-1.5 px-3 py-2 rounded bg-red-600 hover:bg-red-700 text-white font-mono text-xs font-semibold shadow transition-all cursor-pointer disabled:opacity-50"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{isBlocking ? 'Blocking...' : 'Block IP Permanently'}</span>
            </button>

            <button
              onClick={handleUnblock}
              disabled={isUnblocking}
              className="flex items-center gap-1.5 px-3 py-2 rounded bg-[var(--color-accent-soft)] hover:bg-[var(--color-rule)] text-slate-200 border border-[var(--color-rule)] font-mono text-xs font-semibold transition-all cursor-pointer disabled:opacity-50"
            >
              <Unlock className="w-3.5 h-3.5 text-slate-400" />
              <span>{isUnblocking ? 'Unblocking...' : 'Unblock IP'}</span>
            </button>
          </div>

          <button
            onClick={onClose}
            className="w-full sm:w-auto px-5 py-2 rounded bg-[var(--color-paper-2)] hover:bg-[var(--color-rule)] text-slate-300 border border-[var(--color-rule)] font-mono text-xs font-semibold transition-all cursor-pointer"
          >
            Dismiss / Close
          </button>
        </div>
      </div>
    </div>
  );
};
