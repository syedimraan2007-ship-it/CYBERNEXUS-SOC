import React, { useState } from 'react';
import {
  ShieldAlert,
  Flame,
  LayoutDashboard,
  Bell,
  Search,
  Globe,
  Grid,
  FileText,
  RotateCcw,
  User,
  ChevronDown,
} from 'lucide-react';
import { User as UserType } from '../types/soc';

interface NavbarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  currentUser: UserType | null;
  onSwitchUser: (username: string) => void;
  onOpenSirenGuide: () => void;
  onResetDemo: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  currentUser,
  onSwitchUser,
  onOpenSirenGuide,
  onResetDemo,
}) => {
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alerts Queue', icon: Bell },
    { id: 'url_analyzer', label: 'URL Analyzer', icon: Search },
    { id: 'indicator_lookup', label: 'Indicator Lookup', icon: Globe },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Grid },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  return (
    <header className="bg-slate-950 border-b border-slate-800 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
        <div className="flex items-center justify-between h-14">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => onSelectTab('dashboard')}
              className="flex items-center gap-2.5 text-left focus:outline-none"
            >
              <div className="p-1.5 bg-red-600/20 border border-red-500/50 rounded-lg text-red-400">
                <ShieldAlert size={20} />
              </div>
              <div>
                <span className="font-mono font-bold text-sm tracking-wider text-white block">
                  CYBERNEXUS <span className="text-red-400">SOC</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono tracking-tight block -mt-0.5">
                  Detect · Investigate · Explain · Respond
                </span>
              </div>
            </button>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors min-h-[40px] ${
                    isActive
                      ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon size={14} className={isActive ? 'text-red-400' : 'text-slate-400'} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Header Action Controls */}
          <div className="flex items-center gap-2">
            {/* Siren Runbook Launcher */}
            <button
              onClick={onOpenSirenGuide}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-gradient-to-r from-red-950/80 to-slate-900 border border-red-500/40 hover:border-red-500 text-red-300 rounded-lg text-xs font-medium transition-all shadow-sm"
              title="Launch 5-Minute Siren Workflow Guide"
            >
              <Flame size={14} className="text-red-400 animate-pulse" />
              <span className="hidden sm:inline font-mono">Siren Challenge</span>
            </button>

            {/* Reset Demo State Button */}
            <button
              onClick={onResetDemo}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-900 rounded-lg border border-transparent hover:border-slate-800 transition-colors"
              title="Reset Demo Synthetic Alerts"
            >
              <RotateCcw size={14} />
            </button>

            {/* User Dropdown */}
            <div className="relative">
              <button
                onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                className="flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 rounded-lg text-xs font-mono transition-colors"
              >
                <div className="w-5 h-5 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] text-slate-300 font-bold">
                  {currentUser?.name?.charAt(0) || 'A'}
                </div>
                <span className="hidden lg:inline text-slate-300">{currentUser?.name?.split(' ')[0] || 'Analyst'}</span>
                <span className="text-[9px] bg-slate-800 text-slate-400 px-1 py-0.2 rounded border border-slate-700 uppercase">
                  {currentUser?.role || 'ANALYST'}
                </span>
                <ChevronDown size={12} className="text-slate-500" />
              </button>

              {userDropdownOpen && (
                <div className="absolute right-0 mt-1 w-52 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl py-1 z-50 text-xs">
                  <div className="px-3 py-1.5 border-b border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-mono">Active Operator</span>
                    <span className="font-semibold text-slate-200 block">{currentUser?.name}</span>
                    <span className="text-[11px] text-slate-400 block font-mono">{currentUser?.email}</span>
                  </div>
                  <div className="py-1">
                    <span className="px-3 py-1 text-[10px] text-slate-500 uppercase tracking-wider block font-mono">Switch Role:</span>
                    <button
                      onClick={() => {
                        onSwitchUser('analyst1');
                        setUserDropdownOpen(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-slate-300 flex items-center justify-between"
                    >
                      <span>Elena Rostova</span>
                      <span className="text-[10px] text-slate-500 font-mono">ANALYST</span>
                    </button>
                    <button
                      onClick={() => {
                        onSwitchUser('lead_soc');
                        setUserDropdownOpen(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-slate-300 flex items-center justify-between"
                    >
                      <span>Marcus Vance</span>
                      <span className="text-[10px] text-slate-500 font-mono">LEAD</span>
                    </button>
                    <button
                      onClick={() => {
                        onSwitchUser('admin');
                        setUserDropdownOpen(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-slate-300 flex items-center justify-between"
                    >
                      <span>CSO Admin</span>
                      <span className="text-[10px] text-slate-500 font-mono">ADMIN</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
