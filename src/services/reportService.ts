import * as Print from 'expo-print';
import * as Sharing from 'expo-sharing';
import { Platform, Share } from 'react-native';
import { ScanAssessment, UserPreferences } from '../types/security';

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getSeverityHex(severity: string): string {
  switch (severity) {
    case 'Critical':
      return '#FF2E54';
    case 'High':
      return '#FF6B2C';
    case 'Medium':
      return '#F59E0B';
    case 'Low':
      return '#3B82F6';
    default:
      return '#06B6D4';
  }
}

export function buildAssessmentHtmlReport(
  scan: ScanAssessment,
  preferences: UserPreferences
): string {
  const formattedDate = new Date(scan.scanDate).toLocaleString();
  const criticalCount = scan.findings.filter((f) => f.severity === 'Critical').length;
  const highCount = scan.findings.filter((f) => f.severity === 'High').length;
  const mediumCount = scan.findings.filter((f) => f.severity === 'Medium').length;
  const lowCount = scan.findings.filter(
    (f) => f.severity === 'Low' || f.severity === 'Info'
  ).length;

  const findingsHtml =
    scan.findings.length === 0
      ? `<div class="empty-box">No vulnerabilities were detected during this assessment.</div>`
      : scan.findings
          .map(
            (f, idx) => `
        <div class="finding-card">
          <div class="finding-header">
            <div>
              <span class="finding-idx">#${idx + 1}</span>
              <span class="finding-title">${escapeHtml(f.title)}</span>
            </div>
            <div class="badges">
              <span class="mode-badge ${f.mode}">${
                f.mode === 'live' ? 'LIVE CHECK' : 'SIMULATED DEMO'
              }</span>
              <span class="sev-badge" style="background:${getSeverityHex(
                f.severity
              )}">${f.severity.toUpperCase()} • CVSS ${f.cvssScore.toFixed(1)}</span>
            </div>
          </div>
          <div class="meta-row">
            <span><strong>Category:</strong> ${escapeHtml(f.category)}</span>
            <span><strong>CWE:</strong> ${escapeHtml(f.cweId)}</span>
            <span><strong>Vector:</strong> <code>${escapeHtml(f.cvssVector)}</code></span>
          </div>
          <div class="section-block">
            <div class="section-label">Finding Description</div>
            <p>${escapeHtml(f.description)}</p>
          </div>
          <div class="section-block">
            <div class="section-label">Technical Evidence</div>
            <pre class="evidence-box">${escapeHtml(f.evidence)}</pre>
          </div>
          <div class="section-block remediation">
            <div class="section-label">Remediation Recommendation</div>
            <p>${escapeHtml(f.remediation)}</p>
          </div>
        </div>`
          )
          .join('');

  const passedHtml = scan.passedChecks
    .map(
      (c) => `
      <tr>
        <td><strong style="color:#10B981">✓ PASS</strong></td>
        <td>${escapeHtml(c.title)}</td>
        <td>${escapeHtml(c.category)}</td>
        <td>${escapeHtml(c.detail)}</td>
      </tr>`
    )
    .join('');

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>VulnX Security Assessment Report - ${escapeHtml(scan.hostname)}</title>
  <style>
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { margin: 0; padding: 28px; color: #0F172A; background: #FFFFFF; font-size: 12px; line-height: 1.5; }
    .header-banner {
      background: linear-gradient(135deg, #080C16 0%, #141D35 100%);
      color: #FFFFFF;
      padding: 24px;
      border-radius: 12px;
      border-left: 6px solid #E61E2A;
      margin-bottom: 20px;
    }
    .brand-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
    .brand-title { font-size: 22px; font-weight: 800; letter-spacing: 0.5px; color: #FFFFFF; }
    .brand-sub { color: #00E5FF; font-size: 11px; text-transform: uppercase; letter-spacing: 1.2px; }
    .meta-grid { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; font-size: 11px; color: #CBD5E1; }
    .summary-grid { display: flex; gap: 12px; margin-bottom: 22px; }
    .summary-card {
      flex: 1;
      border: 1px solid #E2E8F0;
      border-radius: 10px;
      padding: 14px;
      background: #F8FAFC;
      text-align: center;
    }
    .summary-value { font-size: 22px; font-weight: 800; margin-bottom: 4px; }
    .summary-label { font-size: 10px; text-transform: uppercase; color: #64748B; letter-spacing: 0.6px; }
    h2 { font-size: 15px; color: #0F172A; border-bottom: 2px solid #E2E8F0; padding-bottom: 6px; margin-top: 24px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 18px; font-size: 11px; }
    th, td { border: 1px solid #E2E8F0; padding: 8px 10px; text-align: left; }
    th { background: #F1F5F9; font-weight: 700; color: #334155; }
    .finding-card {
      border: 1px solid #CBD5E1;
      border-radius: 10px;
      padding: 14px;
      margin-bottom: 14px;
      page-break-inside: avoid;
    }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .finding-idx { font-weight: 800; color: #64748B; margin-right: 6px; }
    .finding-title { font-size: 14px; font-weight: 700; color: #0F172A; }
    .badges { display: flex; gap: 6px; align-items: center; }
    .sev-badge { color: #FFF; padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; }
    .mode-badge { padding: 3px 7px; border-radius: 6px; font-size: 9px; font-weight: 700; }
    .mode-badge.live { background: #DCFCE7; color: #166534; }
    .mode-badge.simulated { background: #F3E8FF; color: #6B21A8; }
    .meta-row { display: flex; gap: 16px; font-size: 10.5px; color: #475569; margin-bottom: 10px; background: #F8FAFC; padding: 6px 10px; border-radius: 6px; }
    .section-block { margin-top: 8px; }
    .section-label { font-weight: 700; font-size: 10.5px; text-transform: uppercase; color: #475569; margin-bottom: 3px; }
    .evidence-box { background: #0F172A; color: #38BDF8; padding: 8px 10px; border-radius: 6px; font-family: monospace; font-size: 10.5px; white-space: pre-wrap; word-break: break-all; margin: 4px 0; }
    .remediation { background: #F0FDF4; border-left: 3px solid #10B981; padding: 8px 10px; border-radius: 4px; }
    .footer { margin-top: 28px; text-align: center; font-size: 10px; color: #64748B; border-top: 1px solid #E2E8F0; padding-top: 12px; }
  </style>
</head>
<body>
  <div class="header-banner">
    <div class="brand-row">
      <div>
        <div class="brand-title">🛡️ VulnX Security Assessment Report</div>
        <div class="brand-sub">Mobile Vulnerability & CVSS Risk Intelligence</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:24px;font-weight:900;color:#00E5FF">Grade ${scan.grade}</div>
        <div style="font-size:11px;color:#E2E8F0">Protection Score: ${scan.securityScore}/100</div>
      </div>
    </div>
    <div class="meta-grid">
      <div><strong>Target URL:</strong> ${escapeHtml(scan.targetUrl)}</div>
      <div><strong>Assessment Mode:</strong> ${escapeHtml(scan.scanType)}</div>
      <div><strong>Date:</strong> ${escapeHtml(formattedDate)}</div>
      <div><strong>Analyst:</strong> ${escapeHtml(preferences.analystName)} (${escapeHtml(preferences.organizationName)})</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="summary-value" style="color:#0F172A">${scan.securityScore}/100</div>
      <div class="summary-label">Security Score</div>
    </div>
    <div class="summary-card">
      <div class="summary-value" style="color:#E61E2A">${scan.maxCvssScore.toFixed(1)}</div>
      <div class="summary-label">Peak CVSS v3.1</div>
    </div>
    <div class="summary-card">
      <div class="summary-value" style="color:#FF2E54">${criticalCount + highCount}</div>
      <div class="summary-label">Critical / High</div>
    </div>
    <div class="summary-card">
      <div class="summary-value" style="color:#F59E0B">${mediumCount}</div>
      <div class="summary-label">Medium Risk</div>
    </div>
    <div class="summary-card">
      <div class="summary-value" style="color:#3B82F6">${lowCount}</div>
      <div class="summary-label">Low / Info</div>
    </div>
  </div>

  <h2>1. Network & Transport Telemetry</h2>
  <table>
    <tr>
      <th>Transport Protocol</th>
      <td>${escapeHtml(scan.network.protocol)} (${escapeHtml(scan.network.tlsStatus)})</td>
      <th>HTTP Status / Latency</th>
      <td>HTTP ${scan.network.statusCode} (${scan.network.responseTimeMs} ms)</td>
    </tr>
    <tr>
      <th>Server Banner</th>
      <td>${escapeHtml(scan.network.serverBanner)}</td>
      <th>X-Powered-By</th>
      <td>${escapeHtml(scan.network.poweredBy)}</td>
    </tr>
    <tr>
      <th>Certificate Authority</th>
      <td>${escapeHtml(scan.network.certIssuer)}</td>
      <th>Rate-Limit / Brute-Force Header</th>
      <td>${scan.network.rateLimitDetected ? 'Detected (Active)' : 'Not Detected'}</td>
    </tr>
  </table>

  <h2>2. Vulnerability Findings (${scan.findings.length})</h2>
  ${findingsHtml}

  <h2>3. Passed Security Controls (${scan.passedChecks.length})</h2>
  <table>
    <thead>
      <tr>
        <th style="width:85px">Status</th>
        <th>Control</th>
        <th>Category</th>
        <th>Verification Detail</th>
      </tr>
    </thead>
    <tbody>
      ${passedHtml || '<tr><td colspan="4">No passed checks recorded.</td></tr>'}
    </tbody>
  </table>

  <div class="footer">
    Generated by VulnX Mobile Cybersecurity Assessment Application • Authorized Educational & Defensive Security Report
  </div>
</body>
</html>
  `;
}

export async function generateAndSharePdfReport(
  scan: ScanAssessment,
  preferences: UserPreferences
): Promise<{ uri?: string; shared: boolean }> {
  const html = buildAssessmentHtmlReport(scan, preferences);

  if (Platform.OS === 'web') {
    await Print.printAsync({ html });
    return { shared: true };
  }

  const { uri } = await Print.printToFileAsync({
    html,
    base64: false,
  });

  const canShare = await Sharing.isAvailableAsync();
  if (canShare) {
    await Sharing.shareAsync(uri, {
      mimeType: 'application/pdf',
      dialogTitle: `VulnX Security Report - ${scan.hostname}`,
      UTI: 'com.adobe.pdf',
    });
    return { uri, shared: true };
  }

  return { uri, shared: false };
}

export async function shareAssessmentJsonSummary(
  scan: ScanAssessment
): Promise<void> {
  const payload = {
    reportGenerator: 'VulnX Mobile Security Assessment v1.0',
    exportedAt: new Date().toISOString(),
    targetUrl: scan.targetUrl,
    hostname: scan.hostname,
    scanDate: scan.scanDate,
    scanType: scan.scanType,
    securityScore: scan.securityScore,
    grade: scan.grade,
    maxCvssScore: scan.maxCvssScore,
    riskRating: scan.riskRating,
    network: scan.network,
    findings: scan.findings,
    passedChecks: scan.passedChecks,
  };

  const formattedText = JSON.stringify(payload, null, 2);
  await Share.share({
    title: `VulnX Assessment JSON - ${scan.hostname}`,
    message: formattedText,
  });
}
