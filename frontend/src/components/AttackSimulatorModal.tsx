import React, { useState } from 'react';
import { X, Zap, ShieldAlert, CheckCircle2, Play, Terminal } from 'lucide-react';
import { soundAlert } from '../SoundAlert';
import { apiFetch, apiUrl } from '../api';

interface AttackScenario {
  threat_type: string;
  title: string;
  target: string;
  source_ip: string;
  description: string;
}

interface AttackSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAttackSimulated: () => void;
}

const PRESET_SCENARIOS: AttackScenario[] = [
  {
    threat_type: 'sql_injection',
    title: 'SQL Injection (SQLi)',
    target: '/api/products?category=electronics',
    source_ip: '198.51.100.23',
    description: "Appends `' OR 1=1; DROP TABLE users; --` to extract credentials or corrupt schema."
  },
  {
    threat_type: 'xss',
    title: 'Cross-Site Scripting (XSS)',
    target: '/api/reviews',
    source_ip: '192.0.2.88',
    description: 'Injects executable `<script>` tag attempting to steal document.cookie at checkout.'
  },
  {
    threat_type: 'brute_force',
    title: 'Brute Force / Credential Stuffing',
    target: '/api/auth/login',
    source_ip: '203.0.113.45',
    description: 'Rapid failed login attempts against admin authentication.'
  },
  {
    threat_type: 'ddos',
    title: 'DDoS / Volumetric Flood',
    target: '/api/products',
    source_ip: '45.33.32.156',
    description: 'Volumetric burst of 35 rapid concurrent connections exceeding rate limits.'
  },
  {
    threat_type: 'malware_upload',
    title: 'Malware WebShell Upload',
    target: '/api/upload/avatar',
    source_ip: '185.220.101.5',
    description: 'Uploads `profile.png.php` with embedded PHP shell code.'
  },
  {
    threat_type: 'session_hijacking',
    title: 'Session Hijacking & IP Jump',
    target: '/api/account/orders',
    source_ip: '103.251.167.22',
    description: 'Replays customer session token with anomalous browser fingerprint drift.'
  },
  {
    threat_type: 'api_abuse',
    title: 'API Abuse & Price Tampering',
    target: '/api/checkout',
    source_ip: '198.51.100.23',
    description: 'Modifies checkout payload with price: 0.00 and role: admin.'
  },
  {
    threat_type: 'bot_attack',
    title: 'Bot Inventory Hoarding',
    target: '/api/cart/batch-add',
    source_ip: '203.0.113.45',
    description: 'Automated Scrapy bot reserving limited high-demand inventory.'
  },
  {
    threat_type: 'payment_fraud',
    title: 'Payment Fraud / Card Testing',
    target: '/api/checkout/authorize',
    source_ip: '192.0.2.88',
    description: 'Velocity testing of stolen credit card numbers with $0.99 authorizations.'
  },
  {
    threat_type: 'data_exfiltration',
    title: 'Data Exfiltration / DB Dump',
    target: '/api/customers/export-all',
    source_ip: '185.220.101.5',
    description: 'Attempts unbounded database download via `limit=100000&action=dump`.'
  }
];

export const AttackSimulatorModal: React.FC<AttackSimulatorModalProps> = ({
  isOpen,
  onClose,
  onAttackSimulated
}) => {
  const [selectedScenario, setSelectedScenario] = useState<AttackScenario>(PRESET_SCENARIOS[0]);
  const [customIP, setCustomIP] = useState<string>(PRESET_SCENARIOS[0].source_ip);
  const [customTarget, setCustomTarget] = useState<string>(PRESET_SCENARIOS[0].target);
  const [customPayload, setCustomPayload] = useState<string>('');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [lastResult, setLastResult] = useState<any>(null);

  if (!isOpen) return null;

  const handleSelectScenario = (sc: AttackScenario) => {
    setSelectedScenario(sc);
    setCustomIP(sc.source_ip);
    setCustomTarget(sc.target);
    setCustomPayload('');
    setLastResult(null);
  };

  const handleLaunch = async () => {
    setIsSimulating(true);
    setLastResult(null);
    try {
      const resp = await apiFetch(apiUrl('/api/simulate-attack'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_type: selectedScenario.threat_type,
          source_ip: customIP,
          target: customTarget,
          payload: customPayload || undefined
        })
      });
      const data = await resp.json();
      setLastResult(data);
      soundAlert.playCriticalAlert();
      onAttackSimulated();
    } catch (err) {
      console.error('Failed to trigger simulation:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-[var(--color-paper-2)] border border-[var(--color-rule)] w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="bg-[var(--color-sidebar)] border-b border-[var(--color-rule)] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-red-600/20 border border-red-500/40 text-red-400">
              <Zap className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-mono text-white">
                SENTINEL AI · LIVE ATTACK SIMULATOR
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Select any of the 10 real-world e-commerce attack vectors to test WAF and ML defenses
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
          {/* Scenario Grid */}
          <div>
            <label className="text-xs font-mono font-bold text-slate-300 block mb-2 uppercase tracking-wider">
              1. CHOOSE ATTACK VECTOR (10 Classes Supported)
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {PRESET_SCENARIOS.map(sc => {
                const isSelected = selectedScenario.threat_type === sc.threat_type;
                return (
                  <button
                    key={sc.threat_type}
                    onClick={() => handleSelectScenario(sc)}
                    className={`text-left p-3 rounded-lg border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-[var(--color-accent-soft)] border-[var(--color-accent)] '
                        : 'bg-[var(--color-paper-3)] border-[var(--color-rule)] hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono font-bold text-xs text-white">
                        {sc.title}
                      </span>
                      {isSelected && (
                        <span className="text-[10px] font-mono text-[var(--color-accent)] bg-[var(--color-accent)]/10 px-1.5 py-0.2 rounded border border-[var(--color-accent)]/30">
                          SELECTED
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans line-clamp-2">
                      {sc.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Config fields */}
          <div className="border border-[var(--color-rule)] rounded-lg p-4 bg-[var(--color-paper-3)]/80 space-y-3 font-mono text-xs">
            <h4 className="font-bold text-[var(--color-accent)] uppercase tracking-wider mb-2">
              2. SIMULATION PAYLOAD CONFIGURATION
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Source IP Address:</label>
                <input
                  type="text"
                  value={customIP}
                  onChange={e => setCustomIP(e.target.value)}
                  className="w-full bg-[var(--color-paper-2)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-white focus:outline-none focus:border-[var(--color-accent)]"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Target Endpoint:</label>
                <input
                  type="text"
                  value={customTarget}
                  onChange={e => setCustomTarget(e.target.value)}
                  className="w-full bg-[var(--color-paper-2)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-white focus:outline-none focus:border-[var(--color-accent)]"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Custom Payload Override (Optional):</label>
              <textarea
                placeholder="Leave blank to use pre-configured attack signature..."
                value={customPayload}
                onChange={e => setCustomPayload(e.target.value)}
                rows={2}
                className="w-full bg-[var(--color-paper-2)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-white focus:outline-none focus:border-[var(--color-accent)]"
              />
            </div>
          </div>

          {/* Result card if simulated */}
          {lastResult && (
            <div className="border border-[var(--color-ok)]/40 rounded-lg p-4 bg-[var(--color-ok)]/10 font-mono text-xs">
              <div className="flex items-center gap-2 text-[var(--color-ok)] font-bold mb-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>SIMULATED REQUEST ANALYZED BY SENTINEL AI</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-slate-300">
                <div>
                  <span className="text-slate-400 block">Threat:</span>
                  <span className="text-white font-semibold">{lastResult.threat_type}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Action:</span>
                  <span className="text-red-400 font-bold uppercase">
                    {lastResult.detection_result?.action_taken || 'ANALYZED'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Risk Score:</span>
                  <span className="text-amber-400 font-bold">
                    {lastResult.detection_result?.risk_score || '0.94'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">WAF Status:</span>
                  <span className="text-emerald-400 font-bold">Sentinel demo only</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-[var(--color-sidebar)] border-t border-[var(--color-rule)] px-6 py-4 flex items-center justify-between">
          <span className="text-xs font-mono text-slate-400 hidden sm:inline">
            Local Sentinel detection demo · does not send traffic to the target URL
          </span>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded bg-[var(--color-paper-2)] hover:bg-[var(--color-rule)] text-slate-300 border border-[var(--color-rule)] font-mono text-xs cursor-pointer"
            >
              Cancel
            </button>

            <button
              onClick={handleLaunch}
              disabled={isSimulating}
              className="flex items-center gap-2 px-5 py-2 rounded bg-[var(--color-bad)] hover:brightness-110 text-[var(--color-paper-3)] text-white font-mono text-xs font-bold  transition-all cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isSimulating ? 'Injecting Attack...' : 'Launch Attack Simulation'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
