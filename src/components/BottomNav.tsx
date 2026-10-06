import React from 'react';
import { LayoutDashboard, Bell, Search, FileText, Flame } from 'lucide-react';

interface BottomNavProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  onOpenSirenGuide: () => void;
}

export const BottomNav: React.FC<BottomNavProps> = ({
  activeTab,
  onSelectTab,
  onOpenSirenGuide,
}) => {
  const items = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alerts', icon: Bell },
    { id: 'url_analyzer', label: 'Analyze', icon: Search },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  return (
    <nav
      className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-slate-950/95 backdrop-blur-md border-t border-slate-800 px-2 py-1 safe-area-pb"
      aria-label="Mobile Navigation"
    >
      <div className="flex items-center justify-around">
        {items.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`flex flex-col items-center justify-center min-h-[48px] min-w-[56px] px-2 py-1 rounded-lg transition-colors ${
                isActive
                  ? 'text-red-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon size={18} className={isActive ? 'text-red-400' : 'text-slate-400'} />
              <span className="text-[10px] mt-1 font-mono tracking-tight">{item.label}</span>
            </button>
          );
        })}

        {/* Siren Guide quick button */}
        <button
          onClick={onOpenSirenGuide}
          className="flex flex-col items-center justify-center min-h-[48px] min-w-[56px] px-2 py-1 text-amber-400 hover:text-amber-300 transition-colors"
        >
          <Flame size={18} className="text-amber-400" />
          <span className="text-[10px] mt-1 font-mono tracking-tight">Siren</span>
        </button>
      </div>
    </nav>
  );
};
