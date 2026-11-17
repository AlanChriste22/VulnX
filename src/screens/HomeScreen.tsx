import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import React from 'react';
import {
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { useScanContext } from '../context/ScanContext';
import { COLORS, SEVERITY_CONFIG } from '../theme/colors';
import { ScanAssessment } from '../types/security';

export const HomeScreen: React.FC = () => {
  const { scans, setActiveTab, selectScanAndViewResults } = useScanContext();

  const totalAssessments = scans.length;
  const totalVulnerabilities = scans.reduce(
    (sum, s) => sum + s.findings.length,
    0
  );
  const highRiskFindings = scans.reduce(
    (sum, s) =>
      sum +
      s.findings.filter(
        (f) => f.severity === 'Critical' || f.severity === 'High'
      ).length,
    0
  );

  const avgProtectionScore =
    scans.length > 0
      ? Math.round(
          scans.reduce((sum, s) => sum + s.securityScore, 0) / scans.length
        )
      : 100;

  const highestCvss =
    scans.length > 0
      ? Math.max(...scans.map((s) => s.maxCvssScore), 0).toFixed(1)
      : '0.0';

  const bruteForceAlerts = scans.reduce(
    (sum, s) =>
      sum +
      s.findings.filter((f) => f.category === 'Brute-Force & Auth').length,
    0
  );

  const getScoreColor = (score: number) => {
    if (score >= 80) return COLORS.secure;
    if (score >= 55) return COLORS.medium;
    return COLORS.critical;
  };

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

  const recentScans = scans.slice(0, 4);

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Top Brand Header */}
      <View style={styles.headerRow}>
        <View style={styles.brandLeft}>
          <View style={styles.shieldLogo}>
            <MaterialCommunityIcons
              name="shield-search"
              size={24}
              color={COLORS.white}
            />
          </View>
          <View>
            <View style={styles.titleBadgeRow}>
              <Text style={styles.brandName}>VulnX</Text>
              <View style={styles.proTag}>
                <Text style={styles.proTagText}>SHIELD</Text>
              </View>
            </View>
            <Text style={styles.brandSubtitle}>
              Mobile Web Vulnerability & CVSS Intelligence
            </Text>
          </View>
        </View>
        <TouchableOpacity
          style={styles.quickReportBtn}
          onPress={() => setActiveTab('reports')}
        >
          <Ionicons
            name="document-text-outline"
            size={20}
            color={COLORS.accentCyan}
          />
        </TouchableOpacity>
      </View>

      {/* McAfee / TrustSphere Inspired Protection Hero Card */}
      <View style={styles.heroCard}>
        <View style={styles.heroTop}>
          <View style={styles.scoreRingOuter}>
            <View
              style={[
                styles.scoreRingInner,
                { borderColor: getScoreColor(avgProtectionScore) },
              ]}
            >
              <Text
                style={[
                  styles.scoreValue,
                  { color: getScoreColor(avgProtectionScore) },
                ]}
              >
                {avgProtectionScore}
              </Text>
              <Text style={styles.scoreLabel}>INDEX</Text>
            </View>
          </View>

          <View style={styles.heroDetails}>
            <View style={styles.statusPill}>
              <View
                style={[
                  styles.statusDot,
                  { backgroundColor: getScoreColor(avgProtectionScore) },
                ]}
              />
              <Text style={styles.statusPillText}>
                {avgProtectionScore >= 80
                  ? 'POSTURE: HARDENED'
                  : avgProtectionScore >= 55
                  ? 'POSTURE: ELEVATED RISK'
                  : 'POSTURE: CRITICAL ATTENTION'}
              </Text>
            </View>
            <Text style={styles.heroTitle}>Cyber Defense Overview</Text>
            <Text style={styles.heroDesc}>
              Hybrid assessment engine active for HTTP headers, SSL/TLS,
              brute-force resilience, and CVSS v3.1 scoring.
            </Text>
          </View>
        </View>

        <TouchableOpacity
          style={styles.startScanButton}
          activeOpacity={0.85}
          onPress={() => setActiveTab('scanner')}
        >
          <MaterialCommunityIcons
            name="radar"
            size={20}
            color={COLORS.white}
          />
          <Text style={styles.startScanButtonText}>Start New Website Scan</Text>
          <Ionicons name="arrow-forward" size={18} color={COLORS.white} />
        </TouchableOpacity>
      </View>

      {/* 4 Core KPI Metrics Grid */}
      <View style={styles.metricsGrid}>
        <View style={styles.metricCard}>
          <View style={styles.metricTop}>
            <View
              style={[
                styles.metricIconBox,
                { backgroundColor: COLORS.accentBlueSoft },
              ]}
            >
              <MaterialCommunityIcons
                name="target"
                size={20}
                color={COLORS.accentBlue}
              />
            </View>
            <Text style={styles.metricTag}>TOTAL</Text>
          </View>
          <Text style={styles.metricValue}>{totalAssessments}</Text>
          <Text style={styles.metricLabel}>Total Assessments</Text>
        </View>

        <View style={styles.metricCard}>
          <View style={styles.metricTop}>
            <View
              style={[
                styles.metricIconBox,
                { backgroundColor: COLORS.mediumBg },
              ]}
            >
              <MaterialCommunityIcons
                name="bug-outline"
                size={20}
                color={COLORS.medium}
              />
            </View>
            <Text style={[styles.metricTag, { color: COLORS.medium }]}>
              DETECTED
            </Text>
          </View>
          <Text style={styles.metricValue}>{totalVulnerabilities}</Text>
          <Text style={styles.metricLabel}>Vulnerabilities Detected</Text>
        </View>

        <View style={styles.metricCard}>
          <View style={styles.metricTop}>
            <View
              style={[
                styles.metricIconBox,
                { backgroundColor: COLORS.criticalBg },
              ]}
            >
              <Ionicons
                name="warning-outline"
                size={20}
                color={COLORS.critical}
              />
            </View>
            <Text style={[styles.metricTag, { color: COLORS.critical }]}>
              CVSS ≥ 7.0
            </Text>
          </View>
          <Text style={[styles.metricValue, { color: COLORS.critical }]}>
            {highRiskFindings}
          </Text>
          <Text style={styles.metricLabel}>High-Risk Findings</Text>
        </View>

        <View style={styles.metricCard}>
          <View style={styles.metricTop}>
            <View
              style={[
                styles.metricIconBox,
                { backgroundColor: COLORS.accentPurpleSoft },
              ]}
            >
              <MaterialCommunityIcons
                name="speedometer"
                size={20}
                color={COLORS.accentPurple}
              />
            </View>
            <Text style={[styles.metricTag, { color: COLORS.accentPurple }]}>
              PEAK CVSS
            </Text>
          </View>
          <Text style={styles.metricValue}>{highestCvss}</Text>
          <Text style={styles.metricLabel}>Max CVSS Base Score</Text>
        </View>
      </View>

      {/* McAfee-Style Security Services Matrix */}
      <Text style={styles.sectionTitle}>Active Security Engines</Text>
      <View style={styles.servicesRow}>
        <TouchableOpacity
          style={styles.serviceChip}
          onPress={() => setActiveTab('scanner')}
        >
          <MaterialCommunityIcons
            name="shield-lock-outline"
            size={20}
            color={COLORS.accentCyan}
          />
          <View style={styles.serviceChipTextWrap}>
            <Text style={styles.serviceChipTitle}>App Vulnerability</Text>
            <Text style={styles.serviceChipSub}>
              Headers • SQLi • XSS Checks
            </Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.serviceChip}
          onPress={() => setActiveTab('scanner')}
        >
          <MaterialCommunityIcons
            name="lock-alert-outline"
            size={20}
            color={COLORS.high}
          />
          <View style={styles.serviceChipTextWrap}>
            <Text style={styles.serviceChipTitle}>Brute-Force Audit</Text>
            <Text style={styles.serviceChipSub}>
              {bruteForceAlerts} Auth/Rate-Limit Flags
            </Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.serviceChip}
          onPress={() => setActiveTab('results')}
        >
          <MaterialCommunityIcons
            name="access-point-network"
            size={20}
            color={COLORS.secure}
          />
          <View style={styles.serviceChipTextWrap}>
            <Text style={styles.serviceChipTitle}>Network Analysis</Text>
            <Text style={styles.serviceChipSub}>
              TLS • Latency • Banner Recon
            </Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.serviceChip}
          onPress={() => setActiveTab('reports')}
        >
          <MaterialCommunityIcons
            name="file-chart-outline"
            size={20}
            color={COLORS.accentPurple}
          />
          <View style={styles.serviceChipTextWrap}>
            <Text style={styles.serviceChipTitle}>CVSS & PDF Reports</Text>
            <Text style={styles.serviceChipSub}>
              v3.1 Ratings & Export
            </Text>
          </View>
        </TouchableOpacity>
      </View>

      {/* Recent Scans Section */}
      <View style={styles.sectionHeaderRow}>
        <Text style={styles.sectionTitle}>Recent Scans</Text>
        <TouchableOpacity onPress={() => setActiveTab('history')}>
          <Text style={styles.viewAllLink}>View All ({scans.length})</Text>
        </TouchableOpacity>
      </View>

      {recentScans.length === 0 ? (
        <View style={styles.emptyCard}>
          <MaterialCommunityIcons
            name="shield-off-outline"
            size={36}
            color={COLORS.textMuted}
          />
          <Text style={styles.emptyTitle}>No Assessments Yet</Text>
          <Text style={styles.emptySubtitle}>
            Tap "Start New Website Scan" above to inspect a website.
          </Text>
        </View>
      ) : (
        recentScans.map((scan) => {
          const critHigh = scan.findings.filter(
            (f) => f.severity === 'Critical' || f.severity === 'High'
          ).length;

          return (
            <TouchableOpacity
              key={scan.id}
              style={styles.scanRowCard}
              activeOpacity={0.8}
              onPress={() => selectScanAndViewResults(scan)}
            >
              <View
                style={[
                  styles.gradeBadge,
                  {
                    borderColor: getGradeColor(scan.grade),
                    backgroundColor: `${getGradeColor(scan.grade)}18`,
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

              <View style={styles.scanRowCenter}>
                <View style={styles.scanUrlRow}>
                  <Text style={styles.scanHostname} numberOfLines={1}>
                    {scan.hostname}
                  </Text>
                  <View
                    style={[
                      styles.modeMiniTag,
                      {
                        backgroundColor: scan.includedSimulated
                          ? COLORS.accentPurpleSoft
                          : COLORS.accentCyanSoft,
                      },
                    ]}
                  >
                    <Text
                      style={[
                        styles.modeMiniTagText,
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

                <Text style={styles.scanMetaText}>
                  {new Date(scan.scanDate).toLocaleDateString()} •{' '}
                  {scan.findings.length} findings • Max CVSS{' '}
                  {scan.maxCvssScore.toFixed(1)}
                </Text>

                <View style={styles.miniSevRow}>
                  {critHigh > 0 && (
                    <View
                      style={[
                        styles.miniSevPill,
                        { backgroundColor: SEVERITY_CONFIG.Critical.bg },
                      ]}
                    >
                      <Text
                        style={[
                          styles.miniSevText,
                          { color: SEVERITY_CONFIG.Critical.color },
                        ]}
                      >
                        {critHigh} High/Crit
                      </Text>
                    </View>
                  )}
                  <View
                    style={[
                      styles.miniSevPill,
                      { backgroundColor: COLORS.bgCardElevated },
                    ]}
                  >
                    <Text style={styles.miniSevNeutralText}>
                      Score: {scan.securityScore}/100
                    </Text>
                  </View>
                </View>
              </View>

              <Ionicons
                name="chevron-forward"
                size={20}
                color={COLORS.textMuted}
              />
            </TouchableOpacity>
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
    paddingBottom: 32,
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  brandLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  shieldLogo: {
    width: 44,
    height: 44,
    borderRadius: 12,
    backgroundColor: COLORS.brandRed,
    alignItems: 'center',
    justifyContent: 'center',
  },
  titleBadgeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  brandName: {
    fontSize: 22,
    fontWeight: '800',
    color: COLORS.textPrimary,
    letterSpacing: 0.5,
  },
  proTag: {
    backgroundColor: COLORS.brandRedSoft,
    borderWidth: 1,
    borderColor: COLORS.brandRed,
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 5,
  },
  proTagText: {
    color: COLORS.brandRed,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.8,
  },
  brandSubtitle: {
    fontSize: 12,
    color: COLORS.textSecondary,
    marginTop: 1,
  },
  quickReportBtn: {
    width: 40,
    height: 40,
    borderRadius: 10,
    backgroundColor: COLORS.bgCard,
    borderWidth: 1,
    borderColor: COLORS.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  heroCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 18,
    padding: 18,
    borderWidth: 1,
    borderColor: COLORS.borderHighlight,
    marginBottom: 16,
  },
  heroTop: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 16,
    marginBottom: 16,
  },
  scoreRingOuter: {
    width: 88,
    height: 88,
    borderRadius: 44,
    backgroundColor: COLORS.bgPrimary,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 5,
  },
  scoreRingInner: {
    width: 78,
    height: 78,
    borderRadius: 39,
    borderWidth: 4,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scoreValue: {
    fontSize: 24,
    fontWeight: '900',
  },
  scoreLabel: {
    fontSize: 9,
    fontWeight: '700',
    color: COLORS.textMuted,
    letterSpacing: 1,
  },
  heroDetails: {
    flex: 1,
  },
  statusPill: {
    flexDirection: 'row',
    alignItems: 'center',
    alignSelf: 'flex-start',
    backgroundColor: COLORS.bgPrimary,
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 20,
    gap: 6,
    marginBottom: 6,
  },
  statusDot: {
    width: 7,
    height: 7,
    borderRadius: 4,
  },
  statusPillText: {
    fontSize: 10,
    fontWeight: '800',
    color: COLORS.textPrimary,
    letterSpacing: 0.5,
  },
  heroTitle: {
    fontSize: 17,
    fontWeight: '800',
    color: COLORS.textPrimary,
    marginBottom: 4,
  },
  heroDesc: {
    fontSize: 12,
    color: COLORS.textSecondary,
    lineHeight: 17,
  },
  startScanButton: {
    backgroundColor: COLORS.brandRed,
    borderRadius: 12,
    paddingVertical: 13,
    paddingHorizontal: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  startScanButtonText: {
    color: COLORS.white,
    fontSize: 15,
    fontWeight: '800',
    letterSpacing: 0.3,
  },
  metricsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    gap: 10,
    marginBottom: 20,
  },
  metricCard: {
    width: '48.3%',
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  metricTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  metricIconBox: {
    width: 36,
    height: 36,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  metricTag: {
    fontSize: 10,
    fontWeight: '800',
    color: COLORS.accentBlue,
    letterSpacing: 0.5,
  },
  metricValue: {
    fontSize: 24,
    fontWeight: '900',
    color: COLORS.textPrimary,
    marginBottom: 2,
  },
  metricLabel: {
    fontSize: 12,
    color: COLORS.textSecondary,
    fontWeight: '500',
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '800',
    color: COLORS.textPrimary,
    marginBottom: 10,
  },
  servicesRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    gap: 10,
    marginBottom: 20,
  },
  serviceChip: {
    width: '48.3%',
    backgroundColor: COLORS.bgSecondary,
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: COLORS.border,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  serviceChipTextWrap: {
    flex: 1,
  },
  serviceChipTitle: {
    fontSize: 12.5,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  serviceChipSub: {
    fontSize: 10.5,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
  sectionHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  viewAllLink: {
    fontSize: 12.5,
    fontWeight: '700',
    color: COLORS.accentCyan,
  },
  emptyCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    padding: 24,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  emptyTitle: {
    fontSize: 15,
    fontWeight: '700',
    color: COLORS.textPrimary,
    marginTop: 8,
  },
  emptySubtitle: {
    fontSize: 12,
    color: COLORS.textSecondary,
    textAlign: 'center',
    marginTop: 4,
  },
  scanRowCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    padding: 14,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: COLORS.border,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  gradeBadge: {
    width: 44,
    height: 44,
    borderRadius: 12,
    borderWidth: 1.5,
    alignItems: 'center',
    justifyContent: 'center',
  },
  gradeText: {
    fontSize: 19,
    fontWeight: '900',
  },
  scanRowCenter: {
    flex: 1,
  },
  scanUrlRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 3,
  },
  scanHostname: {
    fontSize: 14.5,
    fontWeight: '700',
    color: COLORS.textPrimary,
    flexShrink: 1,
  },
  modeMiniTag: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  modeMiniTagText: {
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 0.4,
  },
  scanMetaText: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    marginBottom: 6,
  },
  miniSevRow: {
    flexDirection: 'row',
    gap: 6,
  },
  miniSevPill: {
    paddingHorizontal: 7,
    paddingVertical: 2,
    borderRadius: 5,
  },
  miniSevText: {
    fontSize: 10,
    fontWeight: '700',
  },
  miniSevNeutralText: {
    fontSize: 10,
    fontWeight: '600',
    color: COLORS.textSecondary,
  },
});
