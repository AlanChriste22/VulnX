export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type FindingCategory =
  | 'HTTP Security Headers'
  | 'HTTPS & SSL/TLS'
  | 'Server Disclosure'
  | 'Brute-Force & Auth'
  | 'Network Analysis'
  | 'App Vulnerability';

export type AssessmentMode = 'live' | 'simulated';

export interface VulnerabilityFinding {
  id: string;
  title: string;
  category: FindingCategory;
  severity: SeverityLevel;
  cvssScore: number;
  cvssVector: string;
  cweId: string;
  mode: AssessmentMode;
  description: string;
  evidence: string;
  remediation: string;
  impact: string;
}

export interface PassedSecurityCheck {
  id: string;
  title: string;
  category: FindingCategory;
  detail: string;
}

export interface NetworkTelemetry {
  protocol: 'HTTPS' | 'HTTP';
  statusCode: number;
  responseTimeMs: number;
  serverBanner: string;
  poweredBy: string;
  tlsStatus: string;
  certIssuer: string;
  certValidity: string;
  hstsEnabled: boolean;
  rateLimitDetected: boolean;
  corsPolicy: string;
  headersCount: number;
  rawHeaders: Record<string, string>;
}

export interface ScanAssessment {
  id: string;
  targetUrl: string;
  hostname: string;
  scanDate: string;
  scanType: 'Standard (Live)' | 'Hybrid (Live + Simulated)';
  includedSimulated: boolean;
  authorizedByUser: boolean;
  securityScore: number; // 0-100 McAfee-inspired protection index
  maxCvssScore: number; // 0.0-10.0
  riskRating: 'Critical Risk' | 'High Risk' | 'Medium Risk' | 'Low Risk' | 'Secure';
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: VulnerabilityFinding[];
  passedChecks: PassedSecurityCheck[];
  network: NetworkTelemetry;
}

export interface UserPreferences {
  defaultIncludeSimulated: boolean;
  requestTimeoutMs: number;
  strictHeaderMode: boolean;
  autoExpandHighRisk: boolean;
  analystName: string;
  organizationName: string;
}

export type ScreenTab = 'home' | 'scanner' | 'results' | 'history' | 'reports';
