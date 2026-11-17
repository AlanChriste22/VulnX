import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import { StatusBar } from 'expo-status-bar';
import React from 'react';
import {
  Platform,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import {
  SafeAreaProvider,
  SafeAreaView,
} from 'react-native-safe-area-context';
import { ScanProvider, useScanContext } from './src/context/ScanContext';
import { HistoryScreen } from './src/screens/HistoryScreen';
import { HomeScreen } from './src/screens/HomeScreen';
import { ReportsSettingsScreen } from './src/screens/ReportsSettingsScreen';
import { ResultsScreen } from './src/screens/ResultsScreen';
import { ScannerScreen } from './src/screens/ScannerScreen';
import { COLORS } from './src/theme/colors';
import { ScreenTab } from './src/types/security';

const NAV_ITEMS: {
  key: ScreenTab;
  label: string;
  icon: (color: string, focused: boolean) => React.ReactNode;
}[] = [
  {
    key: 'home',
    label: 'Dashboard',
    icon: (color, focused) => (
      <MaterialCommunityIcons
        name={focused ? 'shield-home' : 'shield-home-outline'}
        size={22}
        color={color}
      />
    ),
  },
  {
    key: 'scanner',
    label: 'Scanner',
    icon: (color) => (
      <MaterialCommunityIcons name="radar" size={22} color={color} />
    ),
  },
  {
    key: 'results',
    label: 'Results',
    icon: (color, focused) => (
      <Ionicons
        name={focused ? 'shield-half' : 'shield-half-outline'}
        size={21}
        color={color}
      />
    ),
  },
  {
    key: 'history',
    label: 'History',
    icon: (color, focused) => (
      <Ionicons
        name={focused ? 'time' : 'time-outline'}
        size={22}
        color={color}
      />
    ),
  },
  {
    key: 'reports',
    label: 'Reports',
    icon: (color, focused) => (
      <Ionicons
        name={focused ? 'document-text' : 'document-text-outline'}
        size={21}
        color={color}
      />
    ),
  },
];

const MainShell: React.FC = () => {
  const { activeTab, setActiveTab, selectedScan } = useScanContext();

  const renderScreen = () => {
    switch (activeTab) {
      case 'home':
        return <HomeScreen />;
      case 'scanner':
        return <ScannerScreen />;
      case 'results':
        return <ResultsScreen />;
      case 'history':
        return <HistoryScreen />;
      case 'reports':
        return <ReportsSettingsScreen />;
      default:
        return <HomeScreen />;
    }
  };

  return (
    <SafeAreaView style={styles.safeArea} edges={['top', 'left', 'right']}>
      <StatusBar style="light" />
      <View style={styles.screenWrapper}>{renderScreen()}</View>

      {/* 5-Screen Bottom Navigation Bar */}
      <View style={styles.bottomBar}>
        {NAV_ITEMS.map((item) => {
          const focused = activeTab === item.key;
          const color = focused ? COLORS.accentCyan : COLORS.textMuted;
          const findingCount =
            item.key === 'results' && selectedScan
              ? selectedScan.findings.length
              : 0;

          return (
            <TouchableOpacity
              key={item.key}
              style={styles.tabItem}
              activeOpacity={0.8}
              onPress={() => setActiveTab(item.key)}
            >
              <View style={styles.iconContainer}>
                {item.icon(color, focused)}
                {findingCount > 0 && (
                  <View style={styles.badgeDot}>
                    <Text style={styles.badgeDotText}>
                      {findingCount > 9 ? '9+' : findingCount}
                    </Text>
                  </View>
                )}
              </View>
              <Text
                style={[
                  styles.tabLabel,
                  focused && styles.tabLabelActive,
                ]}
              >
                {item.label}
              </Text>
              {focused && <View style={styles.activeIndicator} />}
            </TouchableOpacity>
          );
        })}
      </View>
    </SafeAreaView>
  );
};

export default function App() {
  return (
    <SafeAreaProvider>
      <ScanProvider>
        <MainShell />
      </ScanProvider>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.bgPrimary,
  },
  screenWrapper: {
    flex: 1,
  },
  bottomBar: {
    flexDirection: 'row',
    backgroundColor: COLORS.bgSecondary,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    paddingTop: 8,
    paddingBottom: Platform.OS === 'ios' ? 20 : 10,
    paddingHorizontal: 6,
  },
  tabItem: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
  },
  iconContainer: {
    position: 'relative',
    marginBottom: 3,
  },
  badgeDot: {
    position: 'absolute',
    top: -5,
    right: -10,
    backgroundColor: COLORS.brandRed,
    borderRadius: 8,
    minWidth: 16,
    height: 16,
    paddingHorizontal: 3,
    alignItems: 'center',
    justifyContent: 'center',
  },
  badgeDotText: {
    color: COLORS.white,
    fontSize: 9,
    fontWeight: '800',
  },
  tabLabel: {
    fontSize: 10.5,
    fontWeight: '600',
    color: COLORS.textMuted,
  },
  tabLabelActive: {
    color: COLORS.accentCyan,
    fontWeight: '800',
  },
  activeIndicator: {
    width: 18,
    height: 2.5,
    borderRadius: 2,
    backgroundColor: COLORS.accentCyan,
    marginTop: 4,
  },
});
