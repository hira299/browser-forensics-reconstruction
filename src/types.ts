/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface BrowserHistoryItem {
  id: string;
  url: string;
  title: string;
  visitTime: string; // ISO String format
  visitCount?: number;
  typedCount?: number;
  searchQuery?: string;
}

export interface SuspiciousFlag {
  id: string;
  ruleName: string;
  description: string;
  category: "Exfiltration" | "Phishing" | "Evasion" | "Shadow IT" | "Credentials" | "Late Night" | "Info Gathering";
  riskLevel: "Critical" | "High" | "Medium" | "Low";
}

export interface AnalyzedRecord {
  id: string;
  url: string;
  title: string;
  visitTime: string; // ISO Date String
  domain: string;
  searchQuery?: string;
  category: string;
  flags: SuspiciousFlag[];
  threatScore: number; // 0 to 100
}

export interface UserSession {
  id: string;
  startTime: string;
  endTime: string;
  durationMinutes: number;
  recordCount: number;
  records: AnalyzedRecord[];
  primaryActivity: string;
  aggregateThreatScore: number;
  flagCount: number;
}

export interface ForensicMetrics {
  totalRecords: number;
  criticalAlertCount: number;
  highAlertCount: number;
  mediumAlertCount: number;
  lowAlertCount: number;
  threatMultiplier: number; // overall calculated grade (0 - 100)
  uniqueDomainsCount: number;
  lateNightVisitRatio: number; // ratio of 00:00 - 05:00
  exfiltrationTriggerCount: number;
}

export interface AiInvestigationRequest {
  sessionContext?: string;
  records: AnalyzedRecord[];
  customQuestion?: string;
}

export interface AiInvestigationResponse {
  hypothesis: string;
  intentSynthesis: string;
  timelineHighlights: Array<{
    timestamp: string;
    events: string;
    forensicSignificance: string;
  }>;
  riskRating: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  mitigationSteps: string[];
}
