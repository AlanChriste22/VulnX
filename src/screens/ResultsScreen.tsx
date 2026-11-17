import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import React, { useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { useScanContext } from '../context/ScanContext';
import {
  generateAndSharePdfReport,
  shareAssessmentJsonSummary,
} from '../services/reportService';
import { COLORS, SEVERITY_CONFIG } from '../theme/colors';
import { SeverityLevel, VulnerabilityFinding } from '../types/security';

type FilterMode = 'all' | 'live' | 'simulated' | 'high';

export const ResultsScreen: React.FC = () => {
  const { selectedScan, preferences, setActiveTab } = useScanContext();
  const [filter, setFilter] = useState<FilterMode>('all');
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const [exportingPdf, setExportingPdf] = useState(false);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const filteredFindings = useMemo(() => {
    if (!selectedScan) return [];
    return selectedScan.findings.filter((f) => {
      if (filter === 'live') return f.mode === 'live';
      if (filter === 'simulated') return f.mode === 'simulated';
      if (filter === 'high')
        return f.severity === 'Critical' || f.severity === 'High';
      return true;
    });
  }, [selectedScan, filter]);

  if (!selectedScan) {
    return (
      <View style={styles.emptyContainer}>
        <MaterialCommunityIcons
          name="shield-search"
          size={52}
          color={COLORS.textMuted}
        />
        <Text style={styles.emptyTitle}>No Assessment Selected</Text>
        <Text style={styles.emptySub}>
          Run a website security scan or select a previous assessment from Scan
          History.
        </Text>
        <TouchableOpacity
          style={styles.newScanBtn}
          onPress={() => setActiveTab('scanner')}
        >
          <Text style={styles.newScanBtnText}>Go to Website Scanner</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const isExpanded = (finding: VulnerabilityFinding, index: number) => {
    if (expandedIds[finding.id] !== undefined) {
      return expandedIds[finding.id];
    }
    if (
      preferences.autoExpandHighRisk &&
      (finding.severity === 'Critical' || finding.severity === 'High')
    ) {
      return true;
    }
    return index === 0;
  };

  const handleExportPdf = async () => {
    setExportingPdf(true);
    try {
      await generateAndSharePdfReport(selectedScan, preferences);
    } catch (err) {
      Alert.alert(
        'PDF Export Failed',
        err instanceof Error ? err.message : 'Unable to generate PDF report.'
      );
    } finally {
      setExportingPdf(false);
    }
  };

  const handleShareJson = async () => {
    try {
      await shareAssessmentJsonSummary(selectedScan);
    } catch {
      // Ignore share cancellation
    }
  };

  const getSeverityStyle = (sev: SeverityLevel) => SEVERITY_CONFIG[sev];

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Target Summary Banner */}
      <View style={styles.summaryCard}>
        <View style={styles.summaryTopRow}>
          <View style={{ flex: 1 }}>
            <View style={styles.modePillRow}>
              <View
                style={[
                  styles.modePill,
                  {
                    backgroundColor: selectedScan.includedSimulated
                      ? COLORS.accentPurpleSoft
                      : COLORS.accentCyanSoft,
                  },
                ]}
              >
                <Text
                  style={[
                    styles.modePillText,
                    {
                      color: selectedScan.includedSimulated
                        ? COLORS.accentPurple
                        : COLORS.accentCyan,
                    },
                  ]}
                >
                  {selectedScan.scanType.toUpperCase()}
                </Text>
              </View>
              <Text style={styles.scanTimestamp}>
                {new Date(selectedScan.scanDate).toLocaleString()}
              </Text>
            </View>
            <Text style={styles.targetHost}>{selectedScan.hostname}</Text>
            <Text style={styles.targetUrlText} numberOfLines={1}>
              {selectedScan.targetUrl}
            </Text>
          </View>

          <View style={styles.gradeBox}>
            <Text style={styles.gradeLabel}>GRADE</Text>
            <Text style={styles.gradeBig}>{selectedScan.grade}</Text>
          </View>
        </View>

        {/* CVSS & Risk Strip */}
        <View style={styles.kpiStrip}>
          <View style={styles.kpiItem}>
            <Text style={styles.kpiValue}>
              {selectedScan.securityScore}/100
            </Text>
            <Text style={styles.kpiLabel}>Protection Score</Text>
          </View>
          <View style={styles.kpiDivider} />
          <View style={styles.kpiItem}>
            <Text style={[styles.kpiValue, { color: COLORS.critical }]}>
              {selectedScan.maxCvssScore.toFixed(1)}
            </Text>
            <Text style={styles.kpiLabel}>Peak CVSS v3.1</Text>
          </View>
          <View style={styles.kpiDivider} />
          <View style={styles.kpiItem}>
            <Text style={styles.kpiValue}>{selectedScan.findings.length}</Text>
            <Text style={styles.kpiLabel}>Total Findings</Text>
          </View>
        </View>

        {/* Quick Export Actions */}
        <View style={styles.actionRow}>
          <TouchableOpacity
            style={styles.pdfBtn}
            onPress={handleExportPdf}
            disabled={exportingPdf}
          >
            {exportingPdf ? (
              <ActivityIndicator size="small" color={COLORS.white} />
            ) : (
              <MaterialCommunityIcons
                name="file-pdf-box"
                size={19}
                color={COLORS.white}
              />
            )}
            <Text style={styles.pdfBtnText}>Download PDF Report</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.jsonBtn} onPress={handleShareJson}>
            <Ionicons
              name="share-social-outline"
              size={18}
              color={COLORS.accentCyan}
            />
            <Text style={styles.jsonBtnText}>Export JSON</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Network & Transport Telemetry Card */}
      <View style={styles.telemetryCard}>
        <View style={styles.telemetryHeader}>
          <MaterialCommunityIcons
            name="lan-connect"
            size={18}
            color={COLORS.accentCyan}
          />
          <Text style={styles.telemetryTitle}>
            Network, SSL/TLS & Server Telemetry
          </Text>
        </View>
        <View style={styles.telemetryGrid}>
          <View style={styles.telemetryCell}>
            <Text style={styles.telemetryKey}>Transport / SSL</Text>
            <Text
              style={[
                styles.telemetryVal,
                {
                  color:
                    selectedScan.network.protocol === 'HTTPS'
                      ? COLORS.secure
                      : COLORS.critical,
                },
              ]}
            >
              {selectedScan.network.tlsStatus}
            </Text>
          </View>
          <View style={styles.telemetryCell}>
            <Text style={styles.telemetryKey}>Status & Latency</Text>
            <Text style={styles.telemetryVal}>
              HTTP {selectedScan.network.statusCode} •{' '}
              {selectedScan.network.responseTimeMs} ms
            </Text>
          </View>
          <View style={styles.telemetryCell}>
            <Text style={styles.telemetryKey}>Server Banner</Text>
            <Text style={styles.telemetryVal} numberOfLines={1}>
              {selectedScan.network.serverBanner}
            </Text>
          </View>
          <View style={styles.telemetryCell}>
            <Text style={styles.telemetryKey}>Brute-Force / Rate-Limit</Text>
            <Text
              style={[
                styles.telemetryVal,
                {
                  color: selectedScan.network.rateLimitDetected
                    ? COLORS.secure
                    : COLORS.medium,
                },
              ]}
            >
              {selectedScan.network.rateLimitDetected
                ? 'Active Throttling'
                : 'No RateLimit Header'}
            </Text>
          </View>
        </View>
      </View>

      {/* Filter Bar */}
      <View style={styles.filterRow}>
        {(
          [
            { key: 'all', label: `All (${selectedScan.findings.length})` },
            {
              key: 'live',
              label: `Live (${
                selectedScan.findings.filter((f) => f.mode === 'live').length
              })`,
            },
            {
              key: 'simulated',
              label: `Simulated (${
                selectedScan.findings.filter((f) => f.mode === 'simulated')
                  .length
              })`,
            },
            {
              key: 'high',
              label: `CVSS ≥ 7.0 (${
                selectedScan.findings.filter((f) => f.cvssScore >= 7.0).length
              })`,
            },
          ] as const
        ).map((tab) => {
          const active = filter === tab.key;
          return (
            <TouchableOpacity
              key={tab.key}
              style={[styles.filterChip, active && styles.filterChipActive]}
              onPress={() => setFilter(tab.key)}
            >
              <Text
                style={[
                  styles.filterChipText,
                  active && styles.filterChipTextActive,
                ]}
              >
                {tab.label}
              </Text>
            </TouchableOpacity>
          );
        })}
      </View>

      {/* Vulnerability Findings List */}
      <Text style={styles.sectionHeader}>
        Vulnerability Findings ({filteredFindings.length})
      </Text>

      {filteredFindings.length === 0 ? (
        <View style={styles.noFindingsCard}>
          <Ionicons
            name="checkmark-done-circle"
            size={36}
            color={COLORS.secure}
          />
          <Text style={styles.noFindingsTitle}>
            No Matching Findings in This Filter
          </Text>
          <Text style={styles.noFindingsSub}>
            Switch filter tabs above to view other findings or passed security
            controls below.
          </Text>
        </View>
      ) : (
        filteredFindings.map((finding, idx) => {
          const sevStyle = getSeverityStyle(finding.severity);
          const expanded = isExpanded(finding, idx);

          return (
            <View
              key={finding.id}
              style={[
                styles.findingCard,
                { borderLeftColor: sevStyle.color },
              ]}
            >
              <TouchableOpacity
                style={styles.findingHeader}
                activeOpacity={0.8}
                onPress={() => toggleExpand(finding.id)}
              >
                <View style={{ flex: 1 }}>
                  <View style={styles.badgeRow}>
                    <View
                      style={[
                        styles.sevBadge,
                        { backgroundColor: sevStyle.bg },
                      ]}
                    >
                      <Text
                        style={[styles.sevBadgeText, { color: sevStyle.color }]}
                      >
                        {sevStyle.label} • CVSS {finding.cvssScore.toFixed(1)}
                      </Text>
                    </View>

                    <View
                      style={[
                        styles.modeBadge,
                        {
                          backgroundColor:
                            finding.mode === 'live'
                              ? COLORS.secureBg
                              : COLORS.accentPurpleSoft,
                        },
                      ]}
                    >
                      <Text
                        style={[
                          styles.modeBadgeText,
                          {
                            color:
                              finding.mode === 'live'
                                ? COLORS.secure
                                : COLORS.accentPurple,
                          },
                        ]}
                      >
                        {finding.mode === 'live' ? 'LIVE' : 'DEMO'}
                      </Text>
                    </View>

                    <Text style={styles.cweText}>{finding.cweId}</Text>
                  </View>

                  <Text style={styles.findingTitle}>{finding.title}</Text>
                  <Text style={styles.findingCategory}>
                    Category: {finding.category}
                  </Text>
                </View>

                <Ionicons
                  name={expanded ? 'chevron-up' : 'chevron-down'}
                  size={20}
                  color={COLORS.textSecondary}
                />
              </TouchableOpacity>

              {expanded && (
                <View style={styles.findingBody}>
                  <View style={styles.vectorBox}>
                    <Text style={styles.vectorLabel}>CVSS v3.1 Vector:</Text>
                    <Text style={styles.vectorCode}>{finding.cvssVector}</Text>
                  </View>

                  <View style={styles.detailBlock}>
                    <Text style={styles.detailHeading}>
                      Finding Description
                    </Text>
                    <Text style={styles.detailText}>{finding.description}</Text>
                  </View>

                  <View style={styles.detailBlock}>
                    <Text style={styles.detailHeading}>Evidence</Text>
                    <View style={styles.evidenceBox}>
                      <Text style={styles.evidenceCode}>
                        {finding.evidence}
                      </Text>
                    </View>
                  </View>

                  <View style={styles.detailBlock}>
                    <Text style={styles.detailHeading}>Security Impact</Text>
                    <Text style={styles.detailText}>{finding.impact}</Text>
                  </View>

                  <View style={styles.remediationBox}>
                    <View style={styles.remediationHeader}>
                      <MaterialCommunityIcons
                        name="wrench-check-outline"
                        size={16}
                        color={COLORS.secure}
                      />
                      <Text style={styles.remediationHeading}>
                        Remediation Recommendation
                      </Text>
                    </View>
                    <Text style={styles.remediationText}>
                      {finding.remediation}
                    </Text>
                  </View>
                </View>
              )}
            </View>
          );
        })
      )}

      {/* Passed Checks Section */}
      {selectedScan.passedChecks.length > 0 && (
        <>
          <Text style={[styles.sectionHeader, { marginTop: 18 }]}>
            Passed Security Controls ({selectedScan.passedChecks.length})
          </Text>
          {selectedScan.passedChecks.map((check) => (
            <View key={check.id} style={styles.passedCard}>
              <Ionicons
                name="checkmark-circle"
                size={20}
                color={COLORS.secure}
              />
              <View style={{ flex: 1 }}>
                <Text style={styles.passedTitle}>{check.title}</Text>
                <Text style={styles.passedDetail}>{check.detail}</Text>
              </View>
            </View>
          ))}
        </>
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
  emptyContainer: {
    flex: 1,
    backgroundColor: COLORS.bgPrimary,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 28,
  },
  emptyTitle: {
    fontSize: 18,
    fontWeight: '800',
    color: COLORS.textPrimary,
    marginTop: 12,
  },
  emptySub: {
    fontSize: 13,
    color: COLORS.textSecondary,
    textAlign: 'center',
    marginTop: 6,
    marginBottom: 18,
  },
  newScanBtn: {
    backgroundColor: COLORS.brandRed,
    paddingHorizontal: 18,
    paddingVertical: 12,
    borderRadius: 10,
  },
  newScanBtnText: {
    color: COLORS.white,
    fontWeight: '800',
    fontSize: 14,
  },
  summaryCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.borderHighlight,
    marginBottom: 14,
  },
  summaryTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: 12,
    marginBottom: 14,
  },
  modePillRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6,
  },
  modePill: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 5,
  },
  modePillText: {
    fontSize: 9.5,
    fontWeight: '800',
    letterSpacing: 0.5,
  },
  scanTimestamp: {
    fontSize: 11,
    color: COLORS.textMuted,
  },
  targetHost: {
    fontSize: 20,
    fontWeight: '900',
    color: COLORS.textPrimary,
  },
  targetUrlText: {
    fontSize: 12,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
  gradeBox: {
    width: 60,
    height: 64,
    borderRadius: 14,
    backgroundColor: COLORS.bgPrimary,
    borderWidth: 1.5,
    borderColor: COLORS.accentCyan,
    alignItems: 'center',
    justifyContent: 'center',
  },
  gradeLabel: {
    fontSize: 8.5,
    fontWeight: '800',
    color: COLORS.textMuted,
    letterSpacing: 0.6,
  },
  gradeBig: {
    fontSize: 26,
    fontWeight: '900',
    color: COLORS.accentCyan,
  },
  kpiStrip: {
    flexDirection: 'row',
    backgroundColor: COLORS.bgPrimary,
    borderRadius: 12,
    paddingVertical: 10,
    marginBottom: 14,
  },
  kpiItem: {
    flex: 1,
    alignItems: 'center',
  },
  kpiDivider: {
    width: 1,
    backgroundColor: COLORS.border,
  },
  kpiValue: {
    fontSize: 17,
    fontWeight: '800',
    color: COLORS.textPrimary,
  },
  kpiLabel: {
    fontSize: 10.5,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
  actionRow: {
    flexDirection: 'row',
    gap: 10,
  },
  pdfBtn: {
    flex: 1,
    backgroundColor: COLORS.brandRed,
    borderRadius: 10,
    paddingVertical: 11,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  pdfBtnText: {
    color: COLORS.white,
    fontSize: 13,
    fontWeight: '800',
  },
  jsonBtn: {
    backgroundColor: COLORS.bgSecondary,
    borderWidth: 1,
    borderColor: COLORS.accentCyan,
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 11,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  jsonBtnText: {
    color: COLORS.accentCyan,
    fontSize: 12.5,
    fontWeight: '700',
  },
  telemetryCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 14,
  },
  telemetryHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 10,
  },
  telemetryTitle: {
    fontSize: 13.5,
    fontWeight: '800',
    color: COLORS.textPrimary,
  },
  telemetryGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  telemetryCell: {
    width: '48%',
    backgroundColor: COLORS.bgPrimary,
    padding: 10,
    borderRadius: 10,
  },
  telemetryKey: {
    fontSize: 10,
    color: COLORS.textMuted,
    fontWeight: '700',
    textTransform: 'uppercase',
    marginBottom: 3,
  },
  telemetryVal: {
    fontSize: 12,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  filterRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 14,
  },
  filterChip: {
    backgroundColor: COLORS.bgCard,
    borderWidth: 1,
    borderColor: COLORS.border,
    paddingHorizontal: 11,
    paddingVertical: 7,
    borderRadius: 20,
  },
  filterChipActive: {
    backgroundColor: COLORS.accentCyanSoft,
    borderColor: COLORS.accentCyan,
  },
  filterChipText: {
    fontSize: 11.5,
    fontWeight: '700',
    color: COLORS.textSecondary,
  },
  filterChipTextActive: {
    color: COLORS.accentCyan,
  },
  sectionHeader: {
    fontSize: 15,
    fontWeight: '800',
    color: COLORS.textPrimary,
    marginBottom: 10,
  },
  noFindingsCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    padding: 22,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  noFindingsTitle: {
    fontSize: 14,
    fontWeight: '700',
    color: COLORS.textPrimary,
    marginTop: 8,
  },
  noFindingsSub: {
    fontSize: 12,
    color: COLORS.textSecondary,
    textAlign: 'center',
    marginTop: 4,
  },
  findingCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderLeftWidth: 4,
    marginBottom: 12,
    overflow: 'hidden',
  },
  findingHeader: {
    padding: 14,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  badgeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6,
  },
  sevBadge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 5,
  },
  sevBadgeText: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.4,
  },
  modeBadge: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  modeBadgeText: {
    fontSize: 9,
    fontWeight: '800',
  },
  cweText: {
    fontSize: 10.5,
    fontWeight: '700',
    color: COLORS.textMuted,
  },
  findingTitle: {
    fontSize: 14.5,
    fontWeight: '800',
    color: COLORS.textPrimary,
    marginBottom: 3,
  },
  findingCategory: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
  },
  findingBody: {
    paddingHorizontal: 14,
    paddingBottom: 14,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    paddingTop: 12,
  },
  vectorBox: {
    backgroundColor: COLORS.bgPrimary,
    paddingHorizontal: 10,
    paddingVertical: 7,
    borderRadius: 8,
    marginBottom: 10,
  },
  vectorLabel: {
    fontSize: 9.5,
    fontWeight: '700',
    color: COLORS.textMuted,
    textTransform: 'uppercase',
  },
  vectorCode: {
    fontSize: 11,
    color: COLORS.accentCyan,
    fontFamily: 'monospace',
    marginTop: 2,
  },
  detailBlock: {
    marginBottom: 10,
  },
  detailHeading: {
    fontSize: 11,
    fontWeight: '800',
    color: COLORS.textSecondary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 4,
  },
  detailText: {
    fontSize: 12.5,
    color: COLORS.textPrimary,
    lineHeight: 18,
  },
  evidenceBox: {
    backgroundColor: COLORS.bgInput,
    borderWidth: 1,
    borderColor: COLORS.borderHighlight,
    borderRadius: 8,
    padding: 10,
  },
  evidenceCode: {
    fontSize: 11.5,
    color: COLORS.accentCyan,
    fontFamily: 'monospace',
    lineHeight: 16,
  },
  remediationBox: {
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
    borderLeftWidth: 3,
    borderLeftColor: COLORS.secure,
    borderRadius: 8,
    padding: 10,
    marginTop: 4,
  },
  remediationHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginBottom: 4,
  },
  remediationHeading: {
    fontSize: 11.5,
    fontWeight: '800',
    color: COLORS.secure,
    textTransform: 'uppercase',
  },
  remediationText: {
    fontSize: 12.5,
    color: COLORS.textPrimary,
    lineHeight: 18,
  },
  passedCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: COLORS.border,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginBottom: 8,
  },
  passedTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  passedDetail: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
});
