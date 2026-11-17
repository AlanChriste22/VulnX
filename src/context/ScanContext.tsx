import AsyncStorage from '@react-native-async-storage/async-storage';
import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  INITIAL_SAMPLE_SCANS,
  runWebsiteSecurityScan,
  ScanStepProgress,
} from '../services/scannerService';
import {
  ScanAssessment,
  ScreenTab,
  UserPreferences,
} from '../types/security';

const SCANS_STORAGE_KEY = '@vulnx_scan_history_v1';
const PREFS_STORAGE_KEY = '@vulnx_user_prefs_v1';

const DEFAULT_PREFERENCES: UserPreferences = {
  defaultIncludeSimulated: true,
  requestTimeoutMs: 8000,
  strictHeaderMode: true,
  autoExpandHighRisk: true,
  analystName: 'Security Analyst',
  organizationName: 'VulnX Cyber Defense Lab',
};

interface ScanContextValue {
  scans: ScanAssessment[];
  selectedScan: ScanAssessment | null;
  activeTab: ScreenTab;
  preferences: UserPreferences;
  isScanning: boolean;
  scanProgress: ScanStepProgress | null;
  setActiveTab: (tab: ScreenTab) => void;
  selectScanAndViewResults: (scan: ScanAssessment) => void;
  executeScan: (
    targetUrl: string,
    includeSimulated: boolean
  ) => Promise<ScanAssessment>;
  deleteScan: (scanId: string) => Promise<void>;
  clearAllScans: () => Promise<void>;
  resetDemoScans: () => Promise<void>;
  updatePreferences: (partial: Partial<UserPreferences>) => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | undefined>(undefined);

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [scans, setScans] = useState<ScanAssessment[]>(INITIAL_SAMPLE_SCANS);
  const [selectedScan, setSelectedScan] = useState<ScanAssessment | null>(
    INITIAL_SAMPLE_SCANS[0]
  );
  const [activeTab, setActiveTab] = useState<ScreenTab>('home');
  const [preferences, setPreferences] =
    useState<UserPreferences>(DEFAULT_PREFERENCES);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanStepProgress | null>(
    null
  );

  useEffect(() => {
    (async () => {
      try {
        const [storedScansJson, storedPrefsJson] = await Promise.all([
          AsyncStorage.getItem(SCANS_STORAGE_KEY),
          AsyncStorage.getItem(PREFS_STORAGE_KEY),
        ]);

        if (storedScansJson) {
          const parsed: ScanAssessment[] = JSON.parse(storedScansJson);
          if (Array.isArray(parsed) && parsed.length > 0) {
            setScans(parsed);
            setSelectedScan(parsed[0]);
          }
        } else {
          await AsyncStorage.setItem(
            SCANS_STORAGE_KEY,
            JSON.stringify(INITIAL_SAMPLE_SCANS)
          );
        }

        if (storedPrefsJson) {
          const parsedPrefs = JSON.parse(storedPrefsJson);
          setPreferences({ ...DEFAULT_PREFERENCES, ...parsedPrefs });
        }
      } catch {
        // Fallback to in-memory defaults if storage fails
      }
    })();
  }, []);

  const persistScans = async (updated: ScanAssessment[]) => {
    setScans(updated);
    try {
      await AsyncStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Ignore storage write error
    }
  };

  const selectScanAndViewResults = (scan: ScanAssessment) => {
    setSelectedScan(scan);
    setActiveTab('results');
  };

  const executeScan = async (
    targetUrl: string,
    includeSimulated: boolean
  ): Promise<ScanAssessment> => {
    setIsScanning(true);
    setScanProgress({
      stepIndex: 0,
      totalSteps: includeSimulated ? 6 : 5,
      phase: 'Preparing VulnX Security Engine',
      detail: 'Allocating header and transport analyzers...',
      progressPercent: 5,
    });

    try {
      const assessment = await runWebsiteSecurityScan(
        targetUrl,
        includeSimulated,
        preferences,
        (step) => setScanProgress(step)
      );

      const updated = [assessment, ...scans];
      await persistScans(updated);
      setSelectedScan(assessment);
      return assessment;
    } finally {
      setIsScanning(false);
      setScanProgress(null);
    }
  };

  const deleteScan = async (scanId: string) => {
    const updated = scans.filter((s) => s.id !== scanId);
    await persistScans(updated);
    if (selectedScan?.id === scanId) {
      setSelectedScan(updated[0] || null);
    }
  };

  const clearAllScans = async () => {
    await persistScans([]);
    setSelectedScan(null);
  };

  const resetDemoScans = async () => {
    await persistScans(INITIAL_SAMPLE_SCANS);
    setSelectedScan(INITIAL_SAMPLE_SCANS[0]);
  };

  const updatePreferences = async (partial: Partial<UserPreferences>) => {
    const nextPrefs = { ...preferences, ...partial };
    setPreferences(nextPrefs);
    try {
      await AsyncStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(nextPrefs));
    } catch {
      // Ignore storage write error
    }
  };

  return (
    <ScanContext.Provider
      value={{
        scans,
        selectedScan,
        activeTab,
        preferences,
        isScanning,
        scanProgress,
        setActiveTab,
        selectScanAndViewResults,
        executeScan,
        deleteScan,
        clearAllScans,
        resetDemoScans,
        updatePreferences,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export function useScanContext(): ScanContextValue {
  const ctx = useContext(ScanContext);
  if (!ctx) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return ctx;
}
