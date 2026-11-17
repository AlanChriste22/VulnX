import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import React, { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { useScanContext } from '../context/ScanContext';
import {
  generateAndSharePdfReport,
  shareAssessmentJsonSummary,
} from '../services/reportService';
import { COLORS } from '../theme/colors';
import { ScanAssessment } from '../types/security';

export const ReportsSettingsScreen: React.FC = () => {
  const {
    scans,
    selectedScan,
    preferences,
    updatePreferences,
    resetDemoScans,
  } = useScanContext();

  const [busyScanId, setBusyScanId] = useState<string | null>(null);
  const targetScan: ScanAssessment | null = selectedScan || scans[0] || null;

  const handleExportPdf = async (scan: ScanAssessment) => {
    setBusyScanId(scan.id);
    try {
      await generateAndSharePdfReport(scan, preferences);
    } catch (err) {
      Alert.alert(
        'PDF Generation Error',
        err instanceof Error ? err.message : 'Could not generate PDF report.'
      );
    } finally {
      setBusyScanId(null);
    }
  };

  const handleExportJson = async (scan: ScanAssessment) => {
    try {
      await shareAssessmentJsonSummary(scan);
    } catch {
      // Ignore share cancellation
    }
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Header */}
      <View style={styles.headerBlock}>
        <View style={styles.iconBox}>
          <MaterialCommunityIcons
            name="file-certificate-outline"
            size={24}
            color={COLORS.accentCyan}
          />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={styles.screenTitle}>Reports & Settings</Text>
          <Text style={styles.screenSub}>
            Generate downloadable PDF assessments, export JSON, and configure
            scanner preferences
          </Text>
        </View>
      </View>

      {/* Primary Report Generator Card */}
      <View style={styles.card}>
        <Text style={styles.sectionLabel}>
          GENERATE DOWNLOADABLE ASSESSMENT REPORT
        </Text>
        {targetScan ? (
          <>
            <View style={styles.activeReportBox}>
              <View style={{ flex: 1 }}>
                <Text style={styles.activeReportHost}>
                  {targetScan.hostname}
                </Text>
                <Text style={styles.activeReportMeta}>
                  {targetScan.scanType} • Grade {targetScan.grade} •{' '}
                  {targetScan.findings.length} Findings • Peak CVSS{' '}
                  {targetScan.maxCvssScore.toFixed(1)}
                </Text>
                <Text style={styles.activeReportDate}>
                  Scanned: {new Date(targetScan.scanDate).toLocaleString()}
                </Text>
              </View>
              <View style={styles.scoreBadge}>
                <Text style={styles.scoreBadgeText}>
                  {targetScan.securityScore}/100
                </Text>
              </View>
            </View>

            <View style={styles.exportBtnsRow}>
              <TouchableOpacity
                style={styles.pdfPrimaryBtn}
                onPress={() => handleExportPdf(targetScan)}
                disabled={busyScanId === targetScan.id}
              >
                {busyScanId === targetScan.id ? (
                  <ActivityIndicator size="small" color={COLORS.white} />
                ) : (
                  <MaterialCommunityIcons
                    name="file-pdf-box"
                    size={20}
                    color={COLORS.white}
                  />
                )}
                <Text style={styles.pdfPrimaryBtnText}>
                  Generate & Share PDF Report
                </Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={styles.jsonSecondaryBtn}
                onPress={() => handleExportJson(targetScan)}
              >
                <Ionicons
                  name="code-slash-outline"
                  size={18}
                  color={COLORS.accentCyan}
                />
                <Text style={styles.jsonSecondaryBtnText}>
                  Export Raw JSON Assessment
                </Text>
              </TouchableOpacity>
            </View>
          </>
        ) : (
          <Text style={styles.emptyText}>
            No assessments available to export. Run a scan or restore sample
            data below.
          </Text>
        )}

        {/* Quick Export List for Other Recent Scans */}
        {scans.length > 1 && (
          <View style={styles.otherReportsSection}>
            <Text style={styles.subLabel}>QUICK EXPORT RECENT TARGETS</Text>
            {scans.slice(0, 4).map((scan) => (
              <View key={scan.id} style={styles.miniReportRow}>
                <View style={{ flex: 1 }}>
                  <Text style={styles.miniHost}>{scan.hostname}</Text>
                  <Text style={styles.miniMeta}>
                    Grade {scan.grade} • {scan.findings.length} findings •{' '}
                    {new Date(scan.scanDate).toLocaleDateString()}
                  </Text>
                </View>
                <TouchableOpacity
                  style={styles.miniPdfBtn}
                  onPress={() => handleExportPdf(scan)}
                  disabled={busyScanId === scan.id}
                >
                  {busyScanId === scan.id ? (
                    <ActivityIndicator size="small" color={COLORS.accentCyan} />
                  ) : (
                    <>
                      <MaterialCommunityIcons
                        name="download-outline"
                        size={16}
                        color={COLORS.accentCyan}
                      />
                      <Text style={styles.miniPdfBtnText}>PDF</Text>
                    </>
                  )}
                </TouchableOpacity>
              </View>
            ))}
          </View>
        )}
      </View>

      {/* Report Branding & Analyst Preferences */}
      <View style={styles.card}>
        <Text style={styles.sectionLabel}>USER & REPORT PREFERENCES</Text>

        <View style={styles.inputGroup}>
          <Text style={styles.inputLabel}>Analyst / Author Name</Text>
          <TextInput
            style={styles.textInput}
            value={preferences.analystName}
            onChangeText={(val) => updatePreferences({ analystName: val })}
            placeholder="Security Analyst"
            placeholderTextColor={COLORS.textMuted}
          />
        </View>

        <View style={styles.inputGroup}>
          <Text style={styles.inputLabel}>Organization / Lab Title</Text>
          <TextInput
            style={styles.textInput}
            value={preferences.organizationName}
            onChangeText={(val) =>
              updatePreferences({ organizationName: val })
            }
            placeholder="VulnX Cyber Defense Lab"
            placeholderTextColor={COLORS.textMuted}
          />
        </View>

        <View style={styles.prefToggleRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.prefTitle}>
              Default Simulated Findings (Hybrid Mode)
            </Text>
            <Text style={styles.prefDesc}>
              Enable simulated SQLi, XSS, and Brute-Force scenarios by default
              on new scans.
            </Text>
          </View>
          <Switch
            value={preferences.defaultIncludeSimulated}
            onValueChange={(val) =>
              updatePreferences({ defaultIncludeSimulated: val })
            }
            trackColor={{ false: COLORS.border, true: COLORS.accentPurple }}
            thumbColor={COLORS.white}
          />
        </View>

        <View style={styles.divider} />

        <View style={styles.prefToggleRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.prefTitle}>Strict HTTP Header Auditing</Text>
            <Text style={styles.prefDesc}>
              Flag optional defense-in-depth headers such as Referrer-Policy and
              Permissions-Policy.
            </Text>
          </View>
          <Switch
            value={preferences.strictHeaderMode}
            onValueChange={(val) =>
              updatePreferences({ strictHeaderMode: val })
            }
            trackColor={{ false: COLORS.border, true: COLORS.accentCyan }}
            thumbColor={COLORS.white}
          />
        </View>

        <View style={styles.divider} />

        <View style={styles.prefToggleRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.prefTitle}>
              Auto-Expand Critical & High Findings
            </Text>
            <Text style={styles.prefDesc}>
              Automatically expand evidence and remediation sections for CVSS ≥
              7.0 findings.
            </Text>
          </View>
          <Switch
            value={preferences.autoExpandHighRisk}
            onValueChange={(val) =>
              updatePreferences({ autoExpandHighRisk: val })
            }
            trackColor={{ false: COLORS.border, true: COLORS.brandRed }}
            thumbColor={COLORS.white}
          />
        </View>
      </View>

      {/* Application Information Card */}
      <View style={styles.card}>
        <Text style={styles.sectionLabel}>APPLICATION INFORMATION</Text>
        <View style={styles.infoRow}>
          <Text style={styles.infoKey}>Application Name</Text>
          <Text style={styles.infoVal}>VulnX Mobile Security Shield</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.infoKey}>Version / Runtime</Text>
          <Text style={styles.infoVal}>v1.0.0 • Expo Go (iOS & Android)</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.infoKey}>Risk Rating Standard</Text>
          <Text style={styles.infoVal}>CVSS v3.1 Inspired + CWE Mapping</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.infoKey}>Assessment Architecture</Text>
          <Text style={styles.infoVal}>
            Hybrid (Live Passive + Simulated Demo)
          </Text>
        </View>

        <TouchableOpacity
          style={styles.resetDemoBtn}
          onPress={() => {
            resetDemoScans();
            Alert.alert(
              'Demo Data Restored',
              'Sample vulnerability assessments have been restored to your history.'
            );
          }}
        >
          <Ionicons
            name="refresh-circle-outline"
            size={18}
            color={COLORS.textSecondary}
          />
          <Text style={styles.resetDemoText}>
            Restore Default Sample Assessments
          </Text>
        </TouchableOpacity>
      </View>
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
  headerBlock: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 16,
  },
  iconBox: {
    width: 44,
    height: 44,
    borderRadius: 12,
    backgroundColor: COLORS.accentCyanSoft,
    borderWidth: 1,
    borderColor: COLORS.accentCyan,
    alignItems: 'center',
    justifyContent: 'center',
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
  card: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 14,
  },
  sectionLabel: {
    fontSize: 11,
    fontWeight: '800',
    color: COLORS.textSecondary,
    letterSpacing: 0.8,
    marginBottom: 12,
  },
  activeReportBox: {
    backgroundColor: COLORS.bgPrimary,
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.borderHighlight,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 12,
  },
  activeReportHost: {
    fontSize: 16,
    fontWeight: '800',
    color: COLORS.textPrimary,
  },
  activeReportMeta: {
    fontSize: 12,
    color: COLORS.accentCyan,
    fontWeight: '600',
    marginTop: 3,
  },
  activeReportDate: {
    fontSize: 11,
    color: COLORS.textMuted,
    marginTop: 2,
  },
  scoreBadge: {
    backgroundColor: COLORS.bgCardElevated,
    paddingHorizontal: 10,
    paddingVertical: 8,
    borderRadius: 10,
  },
  scoreBadgeText: {
    fontSize: 14,
    fontWeight: '900',
    color: COLORS.textPrimary,
  },
  exportBtnsRow: {
    gap: 10,
  },
  pdfPrimaryBtn: {
    backgroundColor: COLORS.brandRed,
    borderRadius: 12,
    paddingVertical: 13,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  pdfPrimaryBtnText: {
    color: COLORS.white,
    fontSize: 14,
    fontWeight: '800',
  },
  jsonSecondaryBtn: {
    backgroundColor: COLORS.bgSecondary,
    borderWidth: 1,
    borderColor: COLORS.accentCyan,
    borderRadius: 12,
    paddingVertical: 11,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  jsonSecondaryBtnText: {
    color: COLORS.accentCyan,
    fontSize: 13,
    fontWeight: '700',
  },
  emptyText: {
    fontSize: 12.5,
    color: COLORS.textSecondary,
  },
  otherReportsSection: {
    marginTop: 16,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    paddingTop: 12,
  },
  subLabel: {
    fontSize: 10,
    fontWeight: '800',
    color: COLORS.textMuted,
    letterSpacing: 0.6,
    marginBottom: 8,
  },
  miniReportRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  miniHost: {
    fontSize: 13.5,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  miniMeta: {
    fontSize: 11,
    color: COLORS.textSecondary,
  },
  miniPdfBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    backgroundColor: COLORS.accentCyanSoft,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
  },
  miniPdfBtnText: {
    fontSize: 11.5,
    fontWeight: '800',
    color: COLORS.accentCyan,
  },
  inputGroup: {
    marginBottom: 12,
  },
  inputLabel: {
    fontSize: 12,
    fontWeight: '700',
    color: COLORS.textPrimary,
    marginBottom: 6,
  },
  textInput: {
    backgroundColor: COLORS.bgInput,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    paddingHorizontal: 12,
    height: 44,
    color: COLORS.textPrimary,
    fontSize: 14,
  },
  prefToggleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingVertical: 4,
  },
  prefTitle: {
    fontSize: 13.5,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  prefDesc: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    marginTop: 2,
    lineHeight: 16,
  },
  divider: {
    height: 1,
    backgroundColor: COLORS.border,
    marginVertical: 12,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 7,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  infoKey: {
    fontSize: 12.5,
    color: COLORS.textSecondary,
  },
  infoVal: {
    fontSize: 12.5,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  resetDemoBtn: {
    marginTop: 14,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    paddingVertical: 10,
    borderRadius: 10,
    backgroundColor: COLORS.bgSecondary,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  resetDemoText: {
    fontSize: 12.5,
    fontWeight: '700',
    color: COLORS.textSecondary,
  },
});
