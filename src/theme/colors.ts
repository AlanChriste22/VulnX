export const COLORS = {
  // McAfee & TrustSphere inspired dark cybersecurity theme
  bgPrimary: '#080C16',
  bgSecondary: '#0F1629',
  bgCard: '#141D35',
  bgCardElevated: '#1B2746',
  bgInput: '#0B1120',
  border: '#243256',
  borderHighlight: '#33487A',

  // Brand & Accent Colors (McAfee crimson shield + Cyber Cyan/Indigo)
  brandRed: '#E61E2A',
  brandRedSoft: 'rgba(230, 30, 42, 0.16)',
  accentCyan: '#00E5FF',
  accentCyanSoft: 'rgba(0, 229, 255, 0.14)',
  accentBlue: '#3B82F6',
  accentBlueSoft: 'rgba(59, 130, 246, 0.16)',
  accentPurple: '#8B5CF6',
  accentPurpleSoft: 'rgba(139, 92, 246, 0.16)',

  // Severity Colors (CVSS v3.1 aligned)
  critical: '#FF2E54',
  criticalBg: 'rgba(255, 46, 84, 0.16)',
  high: '#FF6B2C',
  highBg: 'rgba(255, 107, 44, 0.16)',
  medium: '#F59E0B',
  mediumBg: 'rgba(245, 158, 11, 0.16)',
  low: '#3B82F6',
  lowBg: 'rgba(59, 130, 246, 0.16)',
  info: '#06B6D4',
  infoBg: 'rgba(6, 182, 212, 0.16)',
  secure: '#10B981',
  secureBg: 'rgba(16, 185, 129, 0.16)',

  // Text Hierarchy
  textPrimary: '#F8FAFC',
  textSecondary: '#94A3B8',
  textMuted: '#64748B',
  white: '#FFFFFF',
};

export const SEVERITY_CONFIG = {
  Critical: {
    color: COLORS.critical,
    bg: COLORS.criticalBg,
    minCvss: 9.0,
    label: 'CRITICAL',
  },
  High: {
    color: COLORS.high,
    bg: COLORS.highBg,
    minCvss: 7.0,
    label: 'HIGH',
  },
  Medium: {
    color: COLORS.medium,
    bg: COLORS.mediumBg,
    minCvss: 4.0,
    label: 'MEDIUM',
  },
  Low: {
    color: COLORS.low,
    bg: COLORS.lowBg,
    minCvss: 0.1,
    label: 'LOW',
  },
  Info: {
    color: COLORS.info,
    bg: COLORS.infoBg,
    minCvss: 0.0,
    label: 'INFO',
  },
} as const;
