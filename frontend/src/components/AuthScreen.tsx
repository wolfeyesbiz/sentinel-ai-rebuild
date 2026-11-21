import React, { useEffect, useState } from 'react';
import { Shield, Eye, EyeOff, LoaderCircle, UserRoundPlus } from 'lucide-react';
import { apiFetch, apiUrl } from '../api';

type DemoAccount = { label: string; email: string; password: string };
type User = { id: string; name: string; email: string };

export const AuthScreen: React.FC<{ onAuthenticated: (user: User) => void }> = ({ onAuthenticated }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [demoAccounts, setDemoAccounts] = useState<DemoAccount[]>([]);

  useEffect(() => {
    apiFetch(apiUrl('/api/auth/demo')).then(r => r.json()).then(data => setDemoAccounts(data.accounts || [])).catch(() => {});
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError(''); setLoading(true);
    try {
      const response = await apiFetch(apiUrl(`/api/auth/${mode === 'login' ? 'login' : 'register'}`), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mode === 'login' ? { email, password } : { name, email, password }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || 'Could not sign in. Please try again.');
      window.sessionStorage.setItem('sentinel_session', result.access_token);
      onAuthenticated(result.user);
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not reach Sentinel AI.'); }
    finally { setLoading(false); }
  };

  const selectDemo = (account: DemoAccount) => { setMode('login'); setEmail(account.email); setPassword(account.password); setError(''); };

  return <main className="flex min-h-screen items-center justify-center bg-[var(--color-paper)] px-4 py-10 text-zinc-100">
    <div className="grid w-full max-w-[900px] overflow-hidden rounded-2xl border border-[var(--color-rule)] bg-[var(--color-paper-2)] md:grid-cols-[1fr_1.05fr]">
      <section className="hidden flex-col justify-between border-r border-[var(--color-rule)] bg-[var(--color-sidebar)] p-9 md:flex">
        <div><div className="flex items-center gap-3"><span className="rounded-xl bg-emerald-500/10 p-3 text-emerald-400"><Shield size={22}/></span><div><div className="font-semibold">Sentinel AI</div><div className="text-xs text-zinc-500">Security console</div></div></div>
          <h1 className="mt-16 text-3xl font-semibold leading-tight">See what’s happening across your demo sites.</h1>
          <p className="mt-4 max-w-sm text-sm leading-6 text-zinc-500">Sign in to review security events, run safe checks, and explore Sentinel’s monitoring tools.</p>
        </div>
        <div className="text-xs text-zinc-600">Demo environment · Use sample data only</div>
      </section>
      <section className="p-6 sm:p-9">
        <div className="mb-7 flex items-center gap-3 md:hidden"><span className="rounded-lg bg-emerald-500/10 p-2.5 text-emerald-400"><Shield size={19}/></span><div><div className="font-semibold">Sentinel AI</div><div className="text-xs text-zinc-500">Security console</div></div></div>
        <div><p className="text-xs text-zinc-500">Welcome to Sentinel AI</p><h2 className="mt-1 text-2xl font-semibold">{mode === 'login' ? 'Sign in to your account' : 'Create your account'}</h2><p className="mt-2 text-sm text-zinc-500">{mode === 'login' ? 'Enter your details to continue to the dashboard.' : 'Create an account to access the demo dashboard.'}</p></div>
        <form className="mt-6 space-y-4" onSubmit={submit}>
          {mode === 'register' && <label className="block text-xs text-zinc-400">Name<input required minLength={2} maxLength={60} autoComplete="name" value={name} onChange={e => setName(e.target.value)} className="mt-1.5 w-full rounded-lg border border-[var(--color-rule-2)] bg-[var(--color-paper-3)] px-3 py-2.5 text-sm text-white outline-none focus:border-emerald-600" placeholder="Your name"/></label>}
          <label className="block text-xs text-zinc-400">Email<input required type="email" maxLength={254} autoComplete="email" value={email} onChange={e => setEmail(e.target.value)} className="mt-1.5 w-full rounded-lg border border-[var(--color-rule-2)] bg-[var(--color-paper-3)] px-3 py-2.5 text-sm text-white outline-none focus:border-emerald-600" placeholder="you@example.com"/></label>
          <label className="block text-xs text-zinc-400">Password<div className="relative mt-1.5"><input required minLength={mode === 'register' ? 10 : 1} maxLength={128} type={showPassword ? 'text' : 'password'} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={e => setPassword(e.target.value)} className="w-full rounded-lg border border-[var(--color-rule-2)] bg-[var(--color-paper-3)] px-3 py-2.5 pr-10 text-sm text-white outline-none focus:border-emerald-600" placeholder={mode === 'register' ? 'At least 10 characters' : 'Enter your password'}/><button type="button" onClick={() => setShowPassword(v => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500" aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></div></label>
          {error && <p role="alert" className="rounded-lg border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">{error}</p>}
          <button disabled={loading} className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:opacity-60">{loading ? <LoaderCircle size={16} className="animate-spin"/> : mode === 'login' ? null : <UserRoundPlus size={16}/>} {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}</button>
        </form>
        <div className="mt-5 text-center text-xs text-zinc-500">{mode === 'login' ? 'New to Sentinel AI?' : 'Already have an account?'} <button onClick={() => {setMode(mode === 'login' ? 'register' : 'login');setError('');}} className="font-medium text-emerald-400 hover:text-emerald-300">{mode === 'login' ? 'Create an account' : 'Sign in'}</button></div>
        {mode === 'login' && demoAccounts.length > 0 && <div className="mt-7 border-t border-[var(--color-rule)] pt-5"><div className="mb-3 flex items-center justify-between"><span className="text-xs font-medium text-zinc-300">Try a demo account</span><span className="text-[10px] text-zinc-600">Public sample credentials</span></div><div className="grid grid-cols-1 gap-2 sm:grid-cols-2">{demoAccounts.map(account => <button key={account.email} onClick={() => selectDemo(account)} className="rounded-lg border border-[var(--color-rule)] bg-[var(--color-paper-3)] p-3 text-left transition hover:border-emerald-800"><span className="block text-xs text-zinc-200">{account.label}</span><span className="mt-1 block truncate text-[10px] text-zinc-500">{account.email}</span></button>)}</div><p className="mt-2 text-[10px] leading-4 text-zinc-600">Demo accounts share one workspace. Created accounts and sessions may reset when this demo is redeployed. Do not use personal or sensitive information.</p></div>}
      </section>
    </div>
  </main>;
};
