import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import React, { useMemo, useState } from 'react';
import {
  Alert,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { useScanContext } from '../context/ScanContext';
import { COLORS, SEVERITY_CONFIG } from '../theme/colors';
import { ScanAssessment } from '../types/security';

export const HistoryScreen: React.FC = () => {
  const {
    scans,
    selectScanAndViewResults,
    deleteScan,
    clearAllScans,
    resetDemoScans,
    setActiveTab,
  } = useScanContext();

  const [searchQuery, setSearchQuery] = useState('');

  const filteredScans = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return scans;
    return scans.filter(
      (s) =>
        s.hostname.toLowerCase().includes(q) ||
        s.targetUrl.toLowerCase().includes(q) ||
        s.riskRating.toLowerCase().includes(q)
    );
  }, [scans, searchQuery]);

  const getGradeColor = (grade: ScanAssessment['grade']) => {
    switch (grade) {
      case 'A':
        return COLORS.secure;
      case 'B':
        return COLORS.accentCyan;
      case 'C':
        return COLORS.medium;
      case 'D':
        return COLORS.high;
      default:
        return COLORS.critical;
    }
  };

  const confirmDelete = (scan: ScanAssessment) => {
    Alert.alert(
      'Delete Assessment',
      `Remove scan record for ${scan.hostname}?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: () => deleteScan(scan.id),
        },
      ]
    );
  };

  const confirmClearAll = () => {
    Alert.alert(
      'Clear Scan History',
      'Are you sure you want to delete all stored assessments?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear All',
          style: 'destructive',
          onPress: () => clearAllScans(),
        },
      ]
    );
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Header */}
      <View style={styles.headerRow}>
        <View>
          <Text style={styles.screenTitle}>Assessment History</Text>
          <Text style={styles.screenSub}>
            {scans.length} saved target assessments • Tap any record to inspect
          </Text>
        </View>
        <View style={styles.headerActions}>
          {scans.length > 0 ? (
            <TouchableOpacity
              style={styles.clearBtn}
              onPress={confirmClearAll}
            >
              <Ionicons
                name="trash-outline"
                size={16}
                color={COLORS.critical}
              />
              <Text style={styles.clearBtnText}>Clear</Text>
            </TouchableOpacity>
          ) : (
            <TouchableOpacity
              style={styles.restoreBtn}
              onPress={resetDemoScans}
            >
              <Ionicons
                name="refresh-outline"
                size={16}
                color={COLORS.accentCyan}
              />
              <Text style={styles.restoreBtnText}>Load Samples</Text>
            </TouchableOpacity>
          )}
        </View>
      </View>

      {/* Search Bar */}
      <View style={styles.searchBox}>
        <Ionicons name="search-outline" size={18} color={COLORS.textMuted} />
        <TextInput
          style={styles.searchInput}
          value={searchQuery}
          onChangeText={setSearchQuery}
          placeholder="Search target domain or risk level..."
          placeholderTextColor={COLORS.textMuted}
          autoCapitalize="none"
          autoCorrect={false}
        />
        {searchQuery.length > 0 && (
          <TouchableOpacity onPress={() => setSearchQuery('')}>
            <Ionicons name="close-circle" size={18} color={COLORS.textMuted} />
          </TouchableOpacity>
        )}
      </View>

      {/* History List */}
      {filteredScans.length === 0 ? (
        <View style={styles.emptyCard}>
          <MaterialCommunityIcons
            name="history"
            size={44}
            color={COLORS.textMuted}
          />
          <Text style={styles.emptyTitle}>No Matching Scan Records</Text>
          <Text style={styles.emptyDesc}>
            Start a new website security scan or reload the sample assessments.
          </Text>
          <View style={styles.emptyBtnRow}>
            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={() => setActiveTab('scanner')}
            >
              <Text style={styles.primaryBtnText}>Start New Scan</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={resetDemoScans}
            >
              <Text style={styles.secondaryBtnText}>Restore Demo Scans</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : (
        filteredScans.map((scan) => {
          const critCount = scan.findings.filter(
            (f) => f.severity === 'Critical'
          ).length;
          const highCount = scan.findings.filter(
            (f) => f.severity === 'High'
          ).length;
          const medCount = scan.findings.filter(
            (f) => f.severity === 'Medium'
          ).length;
          const lowCount = scan.findings.filter(
            (f) => f.severity === 'Low' || f.severity === 'Info'
          ).length;

          return (
            <View key={scan.id} style={styles.historyCard}>
              <TouchableOpacity
                activeOpacity={0.85}
                onPress={() => selectScanAndViewResults(scan)}
              >
                <View style={styles.cardTopRow}>
                  <View
                    style={[
                      styles.gradeBox,
                      {
                        borderColor: getGradeColor(scan.grade),
                        backgroundColor: `${getGradeColor(scan.grade)}15`,
                      },
                    ]}
                  >
                    <Text
                      style={[
                        styles.gradeText,
                        { color: getGradeColor(scan.grade) },
                      ]}
                    >
                      {scan.grade}
                    </Text>
                  </View>

                  <View style={styles.cardTitleWrap}>
                    <View style={styles.hostRow}>
                      <Text style={styles.hostname} numberOfLines={1}>
                        {scan.hostname}
                      </Text>
                      <View
                        style={[
                          styles.scanModeBadge,
                          {
                            backgroundColor: scan.includedSimulated
                              ? COLORS.accentPurpleSoft
                              : COLORS.accentCyanSoft,
                          },
                        ]}
                      >
                        <Text
                          style={[
                            styles.scanModeBadgeText,
                            {
                              color: scan.includedSimulated
                                ? COLORS.accentPurple
                                : COLORS.accentCyan,
                            },
                          ]}
                        >
                          {scan.includedSimulated ? 'HYBRID' : 'LIVE'}
                        </Text>
                      </View>
                    </View>
                    <Text style={styles.urlSub} numberOfLines={1}>
                      {scan.targetUrl}
                    </Text>
                    <Text style={styles.dateText}>
                      {new Date(scan.scanDate).toLocaleString()}
                    </Text>
                  </View>

                  <TouchableOpacity
                    style={styles.deleteIconBtn}
                    onPress={() => confirmDelete(scan)}
                  >
                    <Ionicons
                      name="trash-outline"
                      size={18}
                      color={COLORS.textMuted}
                    />
                  </TouchableOpacity>
                </View>

                {/* Findings Breakdown Bar */}
                <View style={styles.statsStrip}>
                  <View style={styles.statChip}>
                    <Text style={styles.statChipLabel}>Findings:</Text>
                    <Text style={styles.statChipVal}>
                      {scan.findings.length}
                    </Text>
                  </View>
                  <View style={styles.statChip}>
                    <Text style={styles.statChipLabel}>Score:</Text>
                    <Text style={styles.statChipVal}>
                      {scan.securityScore}/100
                    </Text>
                  </View>
                  <View style={styles.statChip}>
                    <Text style={styles.statChipLabel}>Peak CVSS:</Text>
                    <Text
                      style={[
                        styles.statChipVal,
                        {
                          color:
                            scan.maxCvssScore >= 7.0
                              ? COLORS.critical
                              : COLORS.accentCyan,
                        },
                      ]}
                    >
                      {scan.maxCvssScore.toFixed(1)}
                    </Text>
                  </View>
                </View>

                {/* Severity Counters & View CTA */}
                <View style={styles.cardFooter}>
                  <View style={styles.sevCountersRow}>
                    {critCount > 0 && (
                      <View
                        style={[
                          styles.sevPill,
                          { backgroundColor: SEVERITY_CONFIG.Critical.bg },
                        ]}
                      >
                        <Text
                          style={[
                            styles.sevPillText,
                            { color: SEVERITY_CONFIG.Critical.color },
                          ]}
                        >
                          {critCount} Crit
                        </Text>
                      </View>
                    )}
                    {highCount > 0 && (
                      <View
                        style={[
                          styles.sevPill,
                          { backgroundColor: SEVERITY_CONFIG.High.bg },
                        ]}
                      >
                        <Text
                          style={[
                            styles.sevPillText,
                            { color: SEVERITY_CONFIG.High.color },
                          ]}
                        >
                          {highCount} High
                        </Text>
                      </View>
                    )}
                    {medCount > 0 && (
                      <View
                        style={[
                          styles.sevPill,
                          { backgroundColor: SEVERITY_CONFIG.Medium.bg },
                        ]}
                      >
                        <Text
                          style={[
                            styles.sevPillText,
                            { color: SEVERITY_CONFIG.Medium.color },
                          ]}
                        >
                          {medCount} Med
                        </Text>
                      </View>
                    )}
                    {lowCount > 0 && (
                      <View
                        style={[
                          styles.sevPill,
                          { backgroundColor: SEVERITY_CONFIG.Low.bg },
                        ]}
                      >
                        <Text
                          style={[
                            styles.sevPillText,
                            { color: SEVERITY_CONFIG.Low.color },
                          ]}
                        >
                          {lowCount} Low
                        </Text>
                      </View>
                    )}
                  </View>

                  <View style={styles.viewResultLink}>
                    <Text style={styles.viewResultText}>View Results</Text>
                    <Ionicons
                      name="arrow-forward"
                      size={14}
                      color={COLORS.accentCyan}
                    />
                  </View>
                </View>
              </TouchableOpacity>
            </View>
          );
        })
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.bgPrimary,
  },
  content: {
    padding: 16,
    paddingBottom: 36,
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 14,
  },
  screenTitle: {
    fontSize: 19,
    fontWeight: '800',
    color: COLORS.textPrimary,
  },
  screenSub: {
    fontSize: 12,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
  headerActions: {
    flexDirection: 'row',
    gap: 8,
  },
  clearBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    backgroundColor: COLORS.criticalBg,
    paddingHorizontal: 10,
    paddingVertical: 7,
    borderRadius: 8,
  },
  clearBtnText: {
    fontSize: 12,
    fontWeight: '700',
    color: COLORS.critical,
  },
  restoreBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    backgroundColor: COLORS.accentCyanSoft,
    paddingHorizontal: 10,
    paddingVertical: 7,
    borderRadius: 8,
  },
  restoreBtnText: {
    fontSize: 12,
    fontWeight: '700',
    color: COLORS.accentCyan,
  },
  searchBox: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgCard,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: COLORS.border,
    paddingHorizontal: 12,
    height: 46,
    gap: 8,
    marginBottom: 14,
  },
  searchInput: {
    flex: 1,
    color: COLORS.textPrimary,
    fontSize: 14,
  },
  emptyCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 16,
    padding: 28,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  emptyTitle: {
    fontSize: 16,
    fontWeight: '800',
    color: COLORS.textPrimary,
    marginTop: 10,
  },
  emptyDesc: {
    fontSize: 12.5,
    color: COLORS.textSecondary,
    textAlign: 'center',
    marginTop: 4,
    marginBottom: 16,
  },
  emptyBtnRow: {
    flexDirection: 'row',
    gap: 10,
  },
  primaryBtn: {
    backgroundColor: COLORS.brandRed,
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 10,
  },
  primaryBtnText: {
    color: COLORS.white,
    fontWeight: '800',
    fontSize: 13,
  },
  secondaryBtn: {
    backgroundColor: COLORS.bgSecondary,
    borderWidth: 1,
    borderColor: COLORS.accentCyan,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 10,
  },
  secondaryBtnText: {
    color: COLORS.accentCyan,
    fontWeight: '700',
    fontSize: 13,
  },
  historyCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 16,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 12,
  },
  cardTopRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12,
    marginBottom: 12,
  },
  gradeBox: {
    width: 48,
    height: 48,
    borderRadius: 12,
    borderWidth: 1.5,
    alignItems: 'center',
    justifyContent: 'center',
  },
  gradeText: {
    fontSize: 21,
    fontWeight: '900',
  },
  cardTitleWrap: {
    flex: 1,
  },
  hostRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  hostname: {
    fontSize: 15.5,
    fontWeight: '800',
    color: COLORS.textPrimary,
    flexShrink: 1,
  },
  scanModeBadge: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  scanModeBadgeText: {
    fontSize: 9,
    fontWeight: '800',
  },
  urlSub: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
  dateText: {
    fontSize: 11,
    color: COLORS.textMuted,
    marginTop: 2,
  },
  deleteIconBtn: {
    padding: 4,
  },
  statsStrip: {
    flexDirection: 'row',
    backgroundColor: COLORS.bgPrimary,
    borderRadius: 10,
    paddingVertical: 8,
    paddingHorizontal: 12,
    justifyContent: 'space-between',
    marginBottom: 10,
  },
  statChip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 5,
  },
  statChipLabel: {
    fontSize: 11,
    color: COLORS.textSecondary,
  },
  statChipVal: {
    fontSize: 12,
    fontWeight: '800',
    color: COLORS.textPrimary,
  },
  cardFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  sevCountersRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 6,
  },
  sevPill: {
    paddingHorizontal: 7,
    paddingVertical: 3,
    borderRadius: 5,
  },
  sevPillText: {
    fontSize: 10,
    fontWeight: '800',
  },
  viewResultLink: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  viewResultText: {
    fontSize: 12,
    fontWeight: '700',
    color: COLORS.accentCyan,
  },
});
