# VulnX — Mobile Cybersecurity Vulnerability Assessment App

A McAfee-inspired, mobile-first cybersecurity vulnerability assessment application built with **React Native & Expo Go** (iOS & Android).

## Features & 5-Screen Architecture

1. **01. Home Dashboard (`src/screens/HomeScreen.tsx`)**
   - McAfee-style **Protection Index Score Ring** (0–100) and posture status badge
   - KPI summary cards: **Total Assessments**, **Vulnerabilities Detected**, **High-Risk Findings (CVSS ≥ 7.0)**, and **Peak CVSS Score**
   - Active Security Engines matrix (**App Vulnerability**, **Brute-Force Audit**, **Network Analysis**, **CVSS & PDF Reports**)
   - **Recent Scans** list and **Start New Website Scan** CTA button

2. **02. Website Scanner (`src/screens/ScannerScreen.tsx`)**
   - Target Website URL input with one-tap test targets (`example.com`, `owasp.org`, `testphp.vulnweb.com`, `neverssl.com`)
   - **Standard Scan (Real Live Checks)**:
     - HTTP Security Headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`)
     - HTTPS & SSL/TLS Transport Verification
     - Server Banner & Technology Stack Disclosure (`Server`, `X-Powered-By`, `X-AspNet-Version`)
     - Rate-Limiting / Brute-Force Protection Header Inspection (`X-RateLimit-*`, `Retry-After`) & CORS policy check
   - **Include Simulated Findings Toggle (Demo Mode)**:
     - SQL Injection (SQLi) scenario (`CVSS 9.8 Critical`)
     - Reflected Cross-Site Scripting (XSS) scenario (`CVSS 7.4 High`)
     - Weak Authentication & Brute-Force Lockout Bypass scenario (`CVSS 8.1 High`)
     - Exposed Administrative & Network Diagnostic Surface scenario (`CVSS 6.4 Medium`)
   - Mandatory ethical authorization confirmation checkbox and live step-by-step progress console

3. **03. Vulnerability Results (`src/screens/ResultsScreen.tsx`)**
   - Target security grade (`A` to `F`), Protection Score, and Peak CVSS v3.1 score
   - Network, SSL/TLS, Server Banner, and Rate-Limiting telemetry overview
   - Filterable findings list (`All`, `Live`, `Simulated`, `CVSS ≥ 7.0`)
   - Expandable cards showing **Vulnerability Name**, **CVSS Score & Vector**, **CWE ID**, **Finding Description**, **Technical Evidence**, **Security Impact**, and **Remediation Recommendation**
   - Passed Security Controls verification list

4. **04. Scan History (`src/screens/HistoryScreen.tsx`)**
   - Persistent local storage via `@react-native-async-storage/async-storage`
   - Searchable history of previous website assessments with target domain, timestamp, grade badge, and severity breakdown

5. **05. Reports & Settings (`src/screens/ReportsSettingsScreen.tsx`)**
   - One-tap **Downloadable PDF Assessment Report** generation (`expo-print` + `expo-sharing`)
   - Raw **JSON Assessment Export** via native system share sheet
   - Customizable Analyst Name, Organization Name, and scanner preferences

## Quick Start (Expo Go)

```bash
cd VulnX
npx expo start
```

- **Android**: Scan the QR code from the **Expo Go** app on Android, or press `a` to open on a connected Android emulator/device.
- **iOS**: Scan the QR code using the iOS Camera app to launch in **Expo Go**.
