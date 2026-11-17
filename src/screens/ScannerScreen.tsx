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
import { COLORS } from '../theme/colors';

const QUICK_TARGETS = [
  { label: 'example.com', url: 'https://example.com', tag: 'Live Safe' },
  { label: 'owasp.org', url: 'https://owasp.org', tag: 'Hardened' },
  {
    label: 'testphp.vulnweb.com',
    url: 'https://testphp.vulnweb.com',
    tag: 'Demo Lab',
  },
  { label: 'neverssl.com (HTTP)', url: 'http://neverssl.com', tag: 'No SSL' },
];

export const ScannerScreen: React.FC = () => {
  const {
    preferences,
    isScanning,
    scanProgress,
    executeScan,
    setActiveTab,
  } = useScanContext();

  const [targetUrl, setTargetUrl] = useState('https://example.com');
  const [includeSimulated, setIncludeSimulated] = useState(
    preferences.defaultIncludeSimulated
  );
  const [authorized, setAuthorized] = useState(false);

  const handleStartScan = async () => {
    if (!targetUrl.trim()) {
      Alert.alert(
        'Target URL Required',
        'Please enter a website URL or domain name to scan (e.g., https://example.com).'
      );
      return;
    }

    if (!authorized) {
      Alert.alert(
        'Authorization Required',
        'Please confirm that you have permission to assess this target website before starting the scan.'
      );
      return;
    }

    try {
      await executeScan(targetUrl, includeSimulated);
      setActiveTab('results');
    } catch (err) {
      Alert.alert(
        'Scan Error',
        err instanceof Error
          ? err.message
          : 'An unexpected error occurred during the assessment.'
      );
    }
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      keyboardShouldPersistTaps="handled"
      showsVerticalScrollIndicator={false}
    >
      {/* Screen Header */}
      <View style={styles.headerBlock}>
        <View style={styles.headerIconWrap}>
          <MaterialCommunityIcons
            name="radar"
            size={24}
            color={COLORS.accentCyan}
          />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={styles.screenTitle}>Website Vulnerability Scanner</Text>
          <Text style={styles.screenSub}>
            Hybrid Live HTTP Header & Simulated OWASP Risk Assessment
          </Text>
        </View>
      </View>

      {/* URL Input Card */}
      <View style={styles.card}>
        <Text style={styles.fieldLabel}>TARGET WEBSITE URL</Text>
        <View style={styles.urlInputContainer}>
          <Ionicons
            name="globe-outline"
            size={20}
            color={COLORS.accentCyan}
            style={{ marginRight: 8 }}
          />
          <TextInput
            style={styles.urlInput}
            value={targetUrl}
            onChangeText={setTargetUrl}
            placeholder="https://example.com"
            placeholderTextColor={COLORS.textMuted}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
            editable={!isScanning}
          />
          {targetUrl.length > 0 && !isScanning && (
            <TouchableOpacity onPress={() => setTargetUrl('')}>
              <Ionicons
                name="close-circle"
                size={18}
                color={COLORS.textMuted}
              />
            </TouchableOpacity>
          )}
        </View>

        <Text style={styles.quickTargetLabel}>QUICK TEST TARGETS:</Text>
        <View style={styles.quickTargetsWrap}>
          {QUICK_TARGETS.map((item) => {
            const selected = targetUrl.toLowerCase() === item.url.toLowerCase();
            return (
              <TouchableOpacity
                key={item.url}
                style={[
                  styles.quickChip,
                  selected && styles.quickChipSelected,
                ]}
                onPress={() => setTargetUrl(item.url)}
                disabled={isScanning}
              >
                <Text
                  style={[
                    styles.quickChipText,
                    selected && styles.quickChipTextSelected,
                  ]}
                >
                  {item.label}
                </Text>
                <Text style={styles.quickChipBadge}>{item.tag}</Text>
              </TouchableOpacity>
            );
          })}
        </View>
      </View>

      {/* Scan Configuration Card */}
      <View style={styles.card}>
        <Text style={styles.fieldLabel}>ASSESSMENT CONFIGURATION</Text>

        {/* Standard Real Scan (Always Active) */}
        <View style={styles.optionRow}>
          <View style={styles.optionIconWrap}>
            <MaterialCommunityIcons
              name="shield-check-outline"
              size={22}
              color={COLORS.secure}
            />
          </View>
          <View style={styles.optionTextWrap}>
            <View style={styles.optionTitleRow}>
              <Text style={styles.optionTitle}>Standard Scan (Live Checks)</Text>
              <View style={styles.liveTag}>
                <Text style={styles.liveTagText}>REAL LIVE</Text>
              </View>
            </View>
            <Text style={styles.optionDesc}>
              Inspects live HTTP security headers (CSP, HSTS, X-Frame-Options,
              X-Content-Type-Options), HTTPS/TLS status, Server banners, and
              rate-limiting headers.
            </Text>
          </View>
          <Ionicons
            name="checkmark-circle"
            size={22}
            color={COLORS.secure}
          />
        </View>

        <View style={styles.divider} />

        {/* Simulated Findings Toggle */}
        <View style={styles.optionRow}>
          <View
            style={[
              styles.optionIconWrap,
              { backgroundColor: COLORS.accentPurpleSoft },
            ]}
          >
            <MaterialCommunityIcons
              name="flask-outline"
              size={22}
              color={COLORS.accentPurple}
            />
          </View>
          <View style={styles.optionTextWrap}>
            <View style={styles.optionTitleRow}>
              <Text style={styles.optionTitle}>Include Simulated Findings</Text>
              <View style={styles.demoTag}>
                <Text style={styles.demoTagText}>DEMO</Text>
              </View>
            </View>
            <Text style={styles.optionDesc}>
              Adds safe educational scenarios for SQL Injection (SQLi),
              Cross-Site Scripting (XSS), Weak Auth / Brute-Force Lockout, and
              Network Port Exposure with CVSS v3.1 vectors.
            </Text>
          </View>
          <Switch
            value={includeSimulated}
            onValueChange={setIncludeSimulated}
            disabled={isScanning}
            trackColor={{ false: COLORS.border, true: COLORS.accentPurple }}
            thumbColor={COLORS.white}
          />
        </View>
      </View>

      {/* Modules Included Breakdown */}
      <View style={styles.card}>
        <Text style={styles.fieldLabel}>ACTIVE ASSESSMENT MODULES</Text>
        <View style={styles.moduleGrid}>
          <View style={styles.moduleItem}>
            <Ionicons name="checkmark-done" size={16} color={COLORS.secure} />
            <Text style={styles.moduleItemText}>HTTP Security Headers</Text>
          </View>
          <View style={styles.moduleItem}>
            <Ionicons name="checkmark-done" size={16} color={COLORS.secure} />
            <Text style={styles.moduleItemText}>HTTPS & SSL/TLS Config</Text>
          </View>
          <View style={styles.moduleItem}>
            <Ionicons name="checkmark-done" size={16} color={COLORS.secure} />
            <Text style={styles.moduleItemText}>Server Info Disclosure</Text>
          </View>
          <View style={styles.moduleItem}>
            <Ionicons name="checkmark-done" size={16} color={COLORS.secure} />
            <Text style={styles.moduleItemText}>Rate-Limit / Brute-Force</Text>
          </View>
          {includeSimulated && (
            <>
              <View style={styles.moduleItem}>
                <Ionicons
                  name="sparkles"
                  size={15}
                  color={COLORS.accentPurple}
                />
                <Text
                  style={[styles.moduleItemText, { color: COLORS.accentPurple }]}
                >
                  SQL Injection (Demo)
                </Text>
              </View>
              <View style={styles.moduleItem}>
                <Ionicons
                  name="sparkles"
                  size={15}
                  color={COLORS.accentPurple}
                />
                <Text
                  style={[styles.moduleItemText, { color: COLORS.accentPurple }]}
                >
                  Reflected XSS (Demo)
                </Text>
              </View>
            </>
          )}
        </View>
      </View>

      {/* Authorization Confirmation Checkbox */}
      <TouchableOpacity
        style={[
          styles.authCard,
          authorized && styles.authCardChecked,
        ]}
        activeOpacity={0.8}
        onPress={() => !isScanning && setAuthorized(!authorized)}
      >
        <View
          style={[
            styles.checkbox,
            authorized && styles.checkboxSelected,
          ]}
        >
          {authorized && (
            <Ionicons name="checkmark" size={16} color={COLORS.white} />
          )}
        </View>
        <View style={{ flex: 1 }}>
          <Text style={styles.authTitle}>
            Authorization & Ethical Scanning Confirmation
          </Text>
          <Text style={styles.authDesc}>
            I confirm that I own this target domain or have explicit permission
            to perform non-intrusive security configuration checks.
          </Text>
        </View>
      </TouchableOpacity>

      {/* Live Scan Progress Console */}
      {isScanning && scanProgress && (
        <View style={styles.progressCard}>
          <View style={styles.progressHeader}>
            <ActivityIndicator size="small" color={COLORS.accentCyan} />
            <Text style={styles.progressPhase}>{scanProgress.phase}</Text>
            <Text style={styles.progressPercent}>
              {scanProgress.progressPercent}%
            </Text>
          </View>

          <View style={styles.progressBarBg}>
            <View
              style={[
                styles.progressBarFill,
                { width: `${scanProgress.progressPercent}%` },
              ]}
            />
          </View>

          <Text style={styles.progressDetail}>{scanProgress.detail}</Text>
          <Text style={styles.progressStepCount}>
            Step {scanProgress.stepIndex} of {scanProgress.totalSteps} • Passive
            Inspection Engine
          </Text>
        </View>
      )}

      {/* Launch Scan CTA Button */}
      <TouchableOpacity
        style={[
          styles.scanCtaBtn,
          (!authorized || isScanning) && styles.scanCtaBtnDisabled,
        ]}
        activeOpacity={0.85}
        onPress={handleStartScan}
        disabled={isScanning}
      >
        {isScanning ? (
          <>
            <ActivityIndicator size="small" color={COLORS.white} />
            <Text style={styles.scanCtaText}>Running Security Assessment...</Text>
          </>
        ) : (
          <>
            <MaterialCommunityIcons
              name="shield-search"
              size={22}
              color={COLORS.white}
            />
            <Text style={styles.scanCtaText}>
              {includeSimulated
                ? 'Launch Hybrid Security Scan'
                : 'Launch Live Header Scan'}
            </Text>
          </>
        )}
      </TouchableOpacity>
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
  headerIconWrap: {
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
  fieldLabel: {
    fontSize: 11,
    fontWeight: '800',
    color: COLORS.textSecondary,
    letterSpacing: 0.8,
    marginBottom: 10,
  },
  urlInputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgInput,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: COLORS.borderHighlight,
    paddingHorizontal: 12,
    height: 50,
  },
  urlInput: {
    flex: 1,
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '600',
  },
  quickTargetLabel: {
    fontSize: 10,
    fontWeight: '700',
    color: COLORS.textMuted,
    marginTop: 12,
    marginBottom: 8,
    letterSpacing: 0.6,
  },
  quickTargetsWrap: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  quickChip: {
    backgroundColor: COLORS.bgSecondary,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 8,
    paddingHorizontal: 10,
    paddingVertical: 6,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  quickChipSelected: {
    borderColor: COLORS.accentCyan,
    backgroundColor: COLORS.accentCyanSoft,
  },
  quickChipText: {
    fontSize: 12,
    color: COLORS.textPrimary,
    fontWeight: '600',
  },
  quickChipTextSelected: {
    color: COLORS.accentCyan,
    fontWeight: '800',
  },
  quickChipBadge: {
    fontSize: 9.5,
    color: COLORS.textMuted,
    fontWeight: '700',
  },
  optionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  optionIconWrap: {
    width: 40,
    height: 40,
    borderRadius: 10,
    backgroundColor: COLORS.secureBg,
    alignItems: 'center',
    justifyContent: 'center',
  },
  optionTextWrap: {
    flex: 1,
  },
  optionTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 3,
  },
  optionTitle: {
    fontSize: 14,
    fontWeight: '700',
    color: COLORS.textPrimary,
  },
  liveTag: {
    backgroundColor: COLORS.secureBg,
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  liveTagText: {
    fontSize: 9,
    fontWeight: '800',
    color: COLORS.secure,
  },
  demoTag: {
    backgroundColor: COLORS.accentPurpleSoft,
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  demoTagText: {
    fontSize: 9,
    fontWeight: '800',
    color: COLORS.accentPurple,
  },
  optionDesc: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    lineHeight: 16,
  },
  divider: {
    height: 1,
    backgroundColor: COLORS.border,
    marginVertical: 14,
  },
  moduleGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  moduleItem: {
    width: '47%',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  moduleItemText: {
    fontSize: 12,
    color: COLORS.textPrimary,
    fontWeight: '600',
  },
  authCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: 14,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12,
    marginBottom: 16,
  },
  authCardChecked: {
    borderColor: COLORS.secure,
    backgroundColor: 'rgba(16, 185, 129, 0.08)',
  },
  checkbox: {
    width: 22,
    height: 22,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: COLORS.textSecondary,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 2,
  },
  checkboxSelected: {
    backgroundColor: COLORS.secure,
    borderColor: COLORS.secure,
  },
  authTitle: {
    fontSize: 13.5,
    fontWeight: '700',
    color: COLORS.textPrimary,
    marginBottom: 3,
  },
  authDesc: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    lineHeight: 16,
  },
  progressCard: {
    backgroundColor: COLORS.bgInput,
    borderRadius: 14,
    padding: 15,
    borderWidth: 1,
    borderColor: COLORS.accentCyan,
    marginBottom: 16,
  },
  progressHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 10,
  },
  progressPhase: {
    flex: 1,
    fontSize: 13,
    fontWeight: '700',
    color: COLORS.accentCyan,
  },
  progressPercent: {
    fontSize: 13,
    fontWeight: '800',
    color: COLORS.textPrimary,
  },
  progressBarBg: {
    height: 7,
    backgroundColor: COLORS.bgCard,
    borderRadius: 4,
    overflow: 'hidden',
    marginBottom: 8,
  },
  progressBarFill: {
    height: '100%',
    backgroundColor: COLORS.accentCyan,
  },
  progressDetail: {
    fontSize: 11.5,
    color: COLORS.textSecondary,
    fontFamily: 'monospace',
    marginBottom: 4,
  },
  progressStepCount: {
    fontSize: 10.5,
    color: COLORS.textMuted,
    fontWeight: '600',
  },
  scanCtaBtn: {
    backgroundColor: COLORS.brandRed,
    borderRadius: 14,
    paddingVertical: 15,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  scanCtaBtnDisabled: {
    opacity: 0.6,
  },
  scanCtaText: {
    color: COLORS.white,
    fontSize: 15.5,
    fontWeight: '800',
    letterSpacing: 0.3,
  },
});
