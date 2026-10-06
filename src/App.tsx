/**
 * CYBERNEXUS SOC - Main Application Component
 * Tagline: Detect. Investigate. Explain. Respond.
 */

import React, { useState, useEffect } from 'react';
import { Alert, SocDashboardStats, SystemHealthState, User } from './types/soc';
import {
  fetchAlerts,
  fetchHealth,
  fetchAlertById,
  loginUser,
  resetDemoData,
} from './services/api';
import { Navbar } from './components/Navbar';
import { BottomNav } from './components/BottomNav';
import { SystemHealthBanner } from './components/SystemHealthBanner';
import { SirenGuideModal } from './components/SirenGuideModal';
import { DashboardPage } from './pages/DashboardPage';
import { AlertsPage } from './pages/AlertsPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { UrlAnalyzerPage } from './pages/UrlAnalyzerPage';
import { IndicatorLookupPage } from './pages/IndicatorLookupPage';
import { MitreMatrixPage } from './pages/MitreMatrixPage';
import { ReportsPage } from './pages/ReportsPage';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<SocDashboardStats | null>(null);
  const [health, setHealth] = useState<SystemHealthState | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [analyzingUrl, setAnalyzingUrl] = useState<string>('');
  const [currentUser, setCurrentUser] = useState<User | null>({
    id: 'USR-01',
    username: 'analyst1',
    name: 'Elena Rostova',
    role: 'ANALYST',
    email: 'elena.rostova@cyber-nexus.internal',
  });
  const [isSirenGuideOpen, setIsSirenGuideOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Load initial data
  const loadData = async () => {
    try {
      const [alertsRes, healthRes] = await Promise.all([
        fetchAlerts(),
        fetchHealth(),
      ]);
      setAlerts(alertsRes.alerts);
      setStats(alertsRes.stats);
      setHealth(healthRes);
    } catch (err) {
      console.warn('Initial data load warning:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // 30s background sync
    return () => clearInterval(interval);
  }, []);

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlertId(alertId);
    setActiveTab('investigation');
  };

  const handleInvestigateAlert = (alertId: string) => {
    setSelectedAlertId(alertId);
    setActiveTab('investigation');
  };

  const handleOpenUrlAnalyzer = (url?: string) => {
    if (url) setAnalyzingUrl(url);
    setActiveTab('url_analyzer');
  };

  const handleSwitchUser = async (username: string) => {
    try {
      const res = await loginUser(username);
      setCurrentUser(res.user);
    } catch {
      // Fallback local switch
      if (username === 'lead_soc') {
        setCurrentUser({
          id: 'USR-02',
          username: 'lead_soc',
          name: 'Marcus Vance',
          role: 'LEAD',
          email: 'marcus.vance@cyber-nexus.internal',
        });
      } else if (username === 'admin') {
        setCurrentUser({
          id: 'USR-03',
          username: 'admin',
          name: 'Chief Security Officer',
          role: 'ADMIN',
          email: 'cso@cyber-nexus.internal',
        });
      } else {
        setCurrentUser({
          id: 'USR-01',
          username: 'analyst1',
          name: 'Elena Rostova',
          role: 'ANALYST',
          email: 'elena.rostova@cyber-nexus.internal',
        });
      }
    }
  };

  const handleResetDemo = async () => {
    await resetDemoData();
    await loadData();
  };

  const handleAlertUpdated = (updatedAlert: Alert) => {
    setAlerts(prev => prev.map(a => (a.id === updatedAlert.id ? updatedAlert : a)));
  };

  const activeAlert = alerts.find(a => a.id === selectedAlertId) || alerts[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-red-500/30 selection:text-white">
      {/* 1. System Health & Telemetry Status Banner */}
      <SystemHealthBanner health={health} onRefresh={loadData} />

      {/* 2. Main Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        onSelectTab={tab => {
          setActiveTab(tab);
          if (tab !== 'investigation') setSelectedAlertId(null);
        }}
        currentUser={currentUser}
        onSwitchUser={handleSwitchUser}
        onOpenSirenGuide={() => setIsSirenGuideOpen(true)}
        onResetDemo={handleResetDemo}
      />

      {/* 3. Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-4 lg:px-6 pt-4 sm:pt-6">
        {isLoading ? (
          <div className="flex items-center justify-center min-h-[50vh]">
            <div className="flex items-center gap-3 text-sm font-mono text-slate-400">
              <div className="w-4 h-4 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
              <span>Initializing CYBERNEXUS SOC Telemetry...</span>
            </div>
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardPage
                alerts={alerts}
                stats={stats}
                onSelectAlert={handleSelectAlert}
                onInvestigateAlert={handleInvestigateAlert}
                onOpenUrlAnalyzer={handleOpenUrlAnalyzer}
              />
            )}

            {activeTab === 'alerts' && (
              <AlertsPage
                alerts={alerts}
                onSelectAlert={handleSelectAlert}
                onInvestigateAlert={handleInvestigateAlert}
              />
            )}

            {activeTab === 'investigation' && activeAlert && (
              <InvestigationPage
                alert={activeAlert}
                currentUser={currentUser}
                onBack={() => setActiveTab('alerts')}
                onAlertUpdated={handleAlertUpdated}
                onOpenUrlAnalyzer={handleOpenUrlAnalyzer}
              />
            )}

            {activeTab === 'url_analyzer' && (
              <UrlAnalyzerPage
                initialUrl={analyzingUrl}
                onOpenInvestigation={handleInvestigateAlert}
              />
            )}

            {activeTab === 'indicator_lookup' && <IndicatorLookupPage />}

            {activeTab === 'mitre' && <MitreMatrixPage />}

            {activeTab === 'reports' && <ReportsPage alerts={alerts} />}
          </>
        )}
      </main>

      {/* 4. Mobile Bottom Navigation (Visible on phone viewports < 768px) */}
      <BottomNav
        activeTab={activeTab}
        onSelectTab={tab => {
          setActiveTab(tab);
          if (tab !== 'investigation') setSelectedAlertId(null);
        }}
        onOpenSirenGuide={() => setIsSirenGuideOpen(true)}
      />

      {/* 5. 5-Minute Siren Challenge Guide Modal */}
      <SirenGuideModal
        isOpen={isSirenGuideOpen}
        onClose={() => setIsSirenGuideOpen(false)}
        onStartChallenge={(alertId: string) => {
          setSelectedAlertId(alertId);
          setActiveTab('investigation');
        }}
      />
    </div>
  );
}
