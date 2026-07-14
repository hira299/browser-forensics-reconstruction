/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { BrowserHistoryItem, AnalyzedRecord, SuspiciousFlag, UserSession, ForensicMetrics } from "./types";

/**
 * Extract domain name from URL
 */
export function extractDomain(urlString: string): string {
  try {
    const url = new URL(urlString);
    return url.hostname.replace("www.", "");
  } catch {
    // If invalid, extract mock domain or return base
    const match = urlString.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/im);
    return match ? match[1] : urlString;
  }
}

/**
 * Identify if a history item represents a search query and extract it
 */
export function extractSearchQuery(urlString: string, title: string): string | undefined {
  try {
    const url = new URL(urlString);
    if (url.hostname.includes("google.") && url.pathname.includes("/search")) {
      const q = url.searchParams.get("q");
      if (q) return decodeURIComponent(q).replace(/\+/g, " ");
    }
    if (url.hostname.includes("bing.") && url.pathname.includes("/search")) {
      const q = url.searchParams.get("q");
      if (q) return decodeURIComponent(q).replace(/\+/g, " ");
    }
  } catch {
    // Treat title as search query if it explicitly states Search
  }

  const searchKeywords = ["- Google Search", "- Bing Search", "Search Results"];
  for (const kw of searchKeywords) {
    if (title.includes(kw)) {
      return title.split(kw)[0].trim();
    }
  }
  return undefined;
}

/**
 * Automatically categorize a domain or title
 */
export function categorizeItem(domain: string, title: string, path: string = ""): string {
  const d = domain.toLowerCase();
  const t = title.toLowerCase();

  if (d.includes("github") || d.includes("stackoverflow") || d.includes("npm") || d.includes("npmjs") || d.includes("tailwindcss") || d.includes("react") || d.includes("typescript") || d.includes("medium") || d.includes("dev.to") || d.includes("mdn")) {
    return "Development & Engineering";
  }
  if (d.includes("mega.nz") || d.includes("gofile") || d.includes("dropbox") || d.includes("drive.google") || d.includes("wetransfer") || d.includes("mediafire") || d.includes("box.com") || d.includes("sendspace")) {
    return "Cloud Storage & Exfiltration Risk";
  }
  if (d.includes("linkedin") || d.includes("indeed") || d.includes("glassdoor") || d.includes("ziprecruiter") || t.includes("job search") || t.includes("career opportunities") || t.includes("resume builder")) {
    return "Career Routing & Information Gathering";
  }
  if (d.includes("coinbase") || d.includes("metamask") || d.includes("binance") || d.includes("kraken") || d.includes("wellsfargo") || d.includes("chase") || d.includes("paypal") || d.includes("bank") || d.includes("financial") || t.includes("mfa bypass") || t.includes("wallet recovery")) {
    return "Financial & Cryptocurrency";
  }
  if (d.includes("reddit") || d.includes("youtube") || d.includes("twitter") || d.includes("x.com") || d.includes("facebook") || d.includes("instagram") || d.includes("twitch") || d.includes("tiktok") || d.includes("netflix") || d.includes("spotify")) {
    return "Social & Entertainment Media";
  }
  if (d.includes("openai") || d.includes("chatgpt") || d.includes("claude") || d.includes("gemini") || d.includes("notebooklm")) {
    return "Generative AI Systems";
  }
  if (d.includes("-verify-") || d.includes("auth-check") || d.includes("security-auth") || d.includes("free-cracked") || d.includes("bleachbit") || t.includes("malicious") || t.includes("bypass") || t.includes("credential") || t.includes("crack")) {
    return "Suspicious & Defensive Bypass";
  }
  if (d.includes("google") || d.includes("bing") || d.includes("duckduckgo") || d.includes("yahoo")) {
    return "Information Retrieval / Web Search";
  }

  return "General Web Access";
}

/**
 * Apply forensic heuristics to run suspicious flag indicators
 */
export function detectSuspiciousActivity(item: BrowserHistoryItem): SuspiciousFlag[] {
  const flags: SuspiciousFlag[] = [];
  const url = item.url.toLowerCase();
  const title = item.title.toLowerCase();
  const searchQuery = item.searchQuery?.toLowerCase() || "";
  const domain = extractDomain(item.url).toLowerCase();

  // Rule 1: Exfiltration / Unauthorized File Sharing Sites
  const exfilDomains = ["mega.nz", "gofile.io", "wetransfer.com", "mediafire.com", "dropmefiles.com", "sendspace.com"];
  if (exfilDomains.some(d => domain.includes(d))) {
    flags.push({
      id: `flg-${item.id}-exfil`,
      ruleName: "Unauthorized Exfiltration Channel",
      description: `Accessed high-capacity, unmonitored transfer node (${domain}) bypassing secure enterprise clouds.`,
      category: "Exfiltration",
      riskLevel: "High"
    });
  }

  // Rule 2: Exfiltration related queries
  const exfilQueries = ["bypass dlp", "data loss prevention split", "anonymous file upload", "compress folder multi part rar", "scp split split archive", "transfer heavy secure data untracked"];
  if (exfilQueries.some(q => searchQuery.includes(q)) || exfilQueries.some(q => title.includes(q))) {
    flags.push({
      id: `flg-${item.id}-dlp`,
      ruleName: "DLP Bypass Research",
      description: `Searched or browsed materials on escaping enterprise Data Loss Prevention blockades.`,
      category: "Exfiltration",
      riskLevel: "Critical"
    });
  }

  // Rule 3: Defensive Evasion & Erasure Programs
  const evasionKeywords = ["bleachbit", "delete history secure", "clear windows event viewer", "powershell clean browser logs", "disable windows defender registry", "kill edr agent", "how to disable mcafee temporarily"];
  if (evasionKeywords.some(kw => url.includes(kw) || title.includes(kw) || searchQuery.includes(kw))) {
    flags.push({
      id: `flg-${item.id}-evasion`,
      ruleName: "Forensics Erasure & Evasion",
      description: `Investigated methods or fetched programs designed to selectively destroy audit trails and system logs.`,
      category: "Evasion",
      riskLevel: "Critical"
    });
  }

  // Rule 4: Typosquatting & Phishing Signals
  const phishingSigs = ["wells-fargo-support", "security-auth-check.net", "metamask-security-alert-verify", "paypal-login-verify", "standard-routing-number-verification"];
  if (phishingSigs.some(sig => url.includes(sig) || domain.includes(sig))) {
    flags.push({
      id: `flg-${item.id}-phish`,
      ruleName: "Phishing typosquatting target",
      description: `Connected to dynamic lookalike domains mimicking official banking or cryptocurrency login nodes.`,
      category: "Phishing",
      riskLevel: "Critical"
    });
  }

  // Rule 5: Shadow IT / Remote Access Portals
  const shadowITKeywords = ["anydesk", "teamviewer", "chrome remote desktop hack", "proxifier download", "tor browser installation", "get residential proxy", "free vpn proxy extension bypass"];
  if (shadowITKeywords.some(kw => url.includes(kw) || title.includes(kw) || searchQuery.includes(kw))) {
    flags.push({
      id: `flg-${item.id}-shadow`,
      ruleName: "Unapproved Tunneling / Proxy Control",
      description: `Acquired remote terminal software or searched anonymous proxy utilities capable of circumventing network gateways.`,
      category: "Shadow IT",
      riskLevel: "High"
    });
  }

  // Rule 6: Sensitive Data Gathering / Competitor Intel
  const intelKeywords = ["competitor intellectual property", "trade secrets list competitor", "exfiltrate git branch secret key", "private repository leak competitors", "source code dump competitor values"];
  if (intelKeywords.some(kw => title.includes(kw) || searchQuery.includes(kw))) {
    flags.push({
      id: `flg-${item.id}-intel`,
      ruleName: "Targeted Competitive Espionage",
      description: `Formulated explicit queries regarding acquisition and value metrics of competitor intellectual property.`,
      category: "Info Gathering",
      riskLevel: "High"
    });
  }

  // Rule 7: Free Cracked Tools (Potential Infostealer malware loading)
  if (url.includes("free-cracked") || title.includes("keygenerator") || title.includes("forensics toolkit crack") || url.includes("cracked-software") || searchQuery.includes("cracked tool keygen")) {
    flags.push({
      id: `flg-${item.id}-malware`,
      ruleName: "Malware Conduit / Cracked Software Download",
      description: `Visited cracked software portals frequently associated with Trojan horse and info-stealer infill payloads.`,
      category: "Credentials",
      riskLevel: "High"
    });
  }

  // Rule 8: Late Night Sensitive Operations
  try {
    const timestamp = new Date(item.visitTime);
    const hour = timestamp.getHours();
    // Mid night till early morning: 00:00 to 05:00
    if (hour >= 0 && hour < 5) {
      // Trigger late-night flag if mixed with cloud, proxy, bypass, evasion or financial topics
      const isSensitiveActivity = 
        url.includes("mega.nz") || url.includes("gofile") || 
        title.includes("job") || searchQuery !== "" || 
        url.includes("phish") || url.includes("check") || url.includes("bypass") || 
        url.includes("bleachbit") || url.includes("defender") || url.includes("proxy");

      if (isSensitiveActivity) {
        flags.push({
          id: `flg-${item.id}-night`,
          ruleName: "Late Night Action Anomalies",
          description: `Executed research or data commands under off-hours timeline window (00:00 - 05:00).`,
          category: "Late Night",
          riskLevel: "Medium"
        });
      }
    }
  } catch {
    // timestamp formatting error
  }

  return flags;
}

/**
 * Perform complete heuristics mapping on a list of uploaded items
 */
export function analyzeBrowserHistory(rawItems: BrowserHistoryItem[]): AnalyzedRecord[] {
  const records: AnalyzedRecord[] = rawItems.map(raw => {
    // Normalise fields
    const domain = extractDomain(raw.url);
    const searchQuery = raw.searchQuery || extractSearchQuery(raw.url, raw.title);
    const category = categorizeItem(domain, raw.title, raw.url);
    const preppedItem = { ...raw, searchQuery };
    const flags = detectSuspiciousActivity(preppedItem);

    // Calculate threat score based on flags
    let threatScore = 0;
    flags.forEach(f => {
      if (f.riskLevel === "Critical") threatScore += 45;
      else if (f.riskLevel === "High") threatScore += 25;
      else if (f.riskLevel === "Medium") threatScore += 12;
      else if (f.riskLevel === "Low") threatScore += 4;
    });

    threatScore = Math.min(100, threatScore);
    // If no flags, threat score is highly low (default baseline 0 unless some fishy elements)
    if (flags.length === 0) {
      if (category.includes("Defensive Bypass") || category.includes("Risk")) {
        threatScore = 15;
      } else if (category.includes("Financial")) {
        threatScore = 5;
      }
    }

    return {
      id: raw.id || `rec-${Math.random().toString(36).substr(2, 9)}`,
      url: raw.url,
      title: raw.title || raw.url,
      visitTime: raw.visitTime,
      domain,
      searchQuery,
      category,
      flags,
      threatScore,
    };
  });

  // Sort them chronologically by default, latest last for timeline flows
  return records.sort((a, b) => new Date(a.visitTime).getTime() - new Date(b.visitTime).getTime());
}

/**
 * Heavy Algorithm: Reconstruct Raw visits into continuous Active User Sessions (Activity Reconstruction)
 */
export function reconstructSessions(analyzedRecords: AnalyzedRecord[]): UserSession[] {
  if (analyzedRecords.length === 0) return [];

  // Sort chronologically
  const records = [...analyzedRecords].sort((a, b) => new Date(a.visitTime).getTime() - new Date(b.visitTime).getTime());
  
  const sessions: UserSession[] = [];
  let currentSessionRecords: AnalyzedRecord[] = [records[0]];
  let currentStart = new Date(records[0].visitTime);
  let currentLast = new Date(records[0].visitTime);

  const GAP_THRESHOLD_MINUTES = 40;

  for (let i = 1; i < records.length; i++) {
    const record = records[i];
    const recordTime = new Date(record.visitTime);
    
    // Calculate gap in minutes
    const diffMs = recordTime.getTime() - currentLast.getTime();
    const diffMin = diffMs / (1000 * 60);

    if (diffMin <= GAP_THRESHOLD_MINUTES) {
      // Part of the same session
      currentSessionRecords.push(record);
      currentLast = recordTime;
    } else {
      // Close old session & create new one
      sessions.push(createSessionPackage(currentSessionRecords, currentStart, currentLast, sessions.length + 1));
      
      // Reset
      currentSessionRecords = [record];
      currentStart = recordTime;
      currentLast = recordTime;
    }
  }

  // Push final session
  if (currentSessionRecords.length > 0) {
    sessions.push(createSessionPackage(currentSessionRecords, currentStart, currentLast, sessions.length + 1));
  }

  // Order from latest session to oldest for clean listing display
  return sessions.reverse();
}

function createSessionPackage(records: AnalyzedRecord[], start: Date, end: Date, numIndex: number): UserSession {
  const durationMs = end.getTime() - start.getTime();
  let durationMinutes = Math.round(durationMs / (1000 * 60));
  if (durationMinutes === 0) durationMinutes = 1; // baseline 1 minute

  const flagCount = records.reduce((sum, r) => sum + r.flags.length, 0);
  
  // Calculate average or high threat metrics
  const maxThreat = records.length > 0 ? Math.max(...records.map(r => r.threatScore)) : 0;
  const avgThreat = records.length > 0 ? records.reduce((sum, r) => sum + r.threatScore, 0) / records.length : 0;
  // Blend max threat heavily with flag volumes
  const aggregateThreatScore = Math.min(100, Math.round(maxThreat * 0.7 + avgThreat * 0.3 + (flagCount > 2 ? 15 : 0)));

  // Determine top primary category in this session
  const categoryCounts: Record<string, number> = {};
  records.forEach(r => {
    categoryCounts[r.category] = (categoryCounts[r.category] || 0) + 1;
  });

  let primaryActivity = "General Web Intermingling";
  let maxCount = 0;
  Object.entries(categoryCounts).forEach(([cat, count]) => {
    if (count > maxCount) {
      maxCount = count;
      primaryActivity = cat;
    }
  });

  // Override primary activity if specific dangerous flags occur
  const allFlags = records.flatMap(r => r.flags);
  if (allFlags.some(f => f.category === "Exfiltration")) {
    primaryActivity = "Suspicious Data Exfiltration Routing";
  } else if (allFlags.some(f => f.category === "Evasion")) {
    primaryActivity = "Forensic Defenses & Clear Operation";
  } else if (allFlags.some(f => f.category === "Phishing")) {
    primaryActivity = "Phishing Vulnerability Interaction";
  } else if (allFlags.some(f => f.category === "Credentials")) {
    primaryActivity = "Inbound Software Cracks Researching";
  } else if (primaryActivity === "Information Retrieval / Web Search" && records.some(r => r.searchQuery)) {
    // list some search terms
    const recentSearches = records.filter(r => r.searchQuery).map(r => `"${r.searchQuery}"`);
    primaryActivity = `Targeted Search Queries: ${recentSearches.slice(0, 2).join(", ")}`;
  }

  return {
    id: `sess-${numIndex}-${Math.random().toString(36).substr(2, 5)}`,
    startTime: start.toISOString(),
    endTime: end.toISOString(),
    durationMinutes,
    recordCount: records.length,
    records,
    primaryActivity,
    aggregateThreatScore,
    flagCount,
  };
}

/**
 * Gather overall forensic statistical dashboard metrics
 */
export function gatherForensicMetrics(records: AnalyzedRecord[]): ForensicMetrics {
  const totalRecords = records.length;
  if (totalRecords === 0) {
    return {
      totalRecords: 0,
      criticalAlertCount: 0,
      highAlertCount: 0,
      mediumAlertCount: 0,
      lowAlertCount: 0,
      threatMultiplier: 0,
      uniqueDomainsCount: 0,
      lateNightVisitRatio: 0,
      exfiltrationTriggerCount: 0
    };
  }

  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let exfilTriggers = 0;
  let lateNights = 0;

  const domains = new Set<string>();

  records.forEach(r => {
    domains.add(r.domain);
    
    // Count risk levels
    r.flags.forEach(f => {
      if (f.riskLevel === "Critical") critical++;
      if (f.riskLevel === "High") high++;
      if (f.riskLevel === "Medium") medium++;
      if (f.riskLevel === "Low") low++;
      if (f.category === "Exfiltration") exfilTriggers++;
    });

    // Check late night hour
    try {
      const dt = new Date(r.visitTime);
      const hour = dt.getHours();
      if (hour >= 0 && hour < 5) {
        lateNights++;
      }
    } catch {}
  });

  const uniqueDomainsCount = domains.size;
  const lateNightVisitRatio = totalRecords > 0 ? (lateNights / totalRecords) : 0;

  // Calculate overall corporate Threat Index out of 100
  // Formula focuses on heavy impacts of Critical/High flags
  const rawScore = (critical * 35) + (high * 18) + (medium * 8) + (low * 3);
  const threatMultiplier = Math.min(100, Math.round(Math.min(1, Math.max(0, rawScore / 100)) * 100));

  return {
    totalRecords,
    criticalAlertCount: critical,
    highAlertCount: high,
    mediumAlertCount: medium,
    lowAlertCount: low,
    threatMultiplier,
    uniqueDomainsCount,
    lateNightVisitRatio,
    exfiltrationTriggerCount: exfilTriggers
  };
}

/**
 * Helper to parse uploaded browser formats (Chrome JSON history exports, CSV files)
 */
export function parseBrowserHistoryText(rawText: string, fileType: "json" | "csv" | "auto"): BrowserHistoryItem[] {
  let mode: "json" | "csv" = "json";
  
  if (fileType === "auto") {
    const trimmed = rawText.trim();
    if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
      mode = "json";
    } else {
      mode = "csv";
    }
  } else {
    mode = fileType;
  }

  if (mode === "json") {
    try {
      const parsed = JSON.parse(rawText);
      const arrayToParse = Array.isArray(parsed) ? parsed : (parsed.BrowserHistory || parsed.history || []);
      
      return arrayToParse.map((item: any, idx: number) => {
        // Handle various JSON formats exported by different browsers/tools
        const url = item.url || item.Url || item.URL || "";
        const title = item.title || item.Title || item.name || item.domain || url;
        
        // Browser coordinates sometimes multiply timestamps (microseconds/milliseconds)
        let visitTimeRaw = item.visitTime || item.time || item.timestamp || item.visit_time || new Date().toISOString();
        if (typeof visitTimeRaw === "number") {
          // Chrome microsecond epoch check (17 digits or standard 16 digit timestamp from chrome sqlite)
          if (visitTimeRaw > 10000000000000) {
            // Webkit epoch microsecond (microseconds from 1601-01-01)
            // Convert webkit time to standard JS milliseconds
            const msec = Math.round(visitTimeRaw / 1000) - 11644473600000;
            visitTimeRaw = new Date(msec).toISOString();
          } else if (visitTimeRaw > 100000000000) {
            // Milliseconds epoch
            visitTimeRaw = new Date(visitTimeRaw).toISOString();
          } else {
            // Seconds epoch
            visitTimeRaw = new Date(visitTimeRaw * 1000).toISOString();
          }
        }

        return {
          id: item.id || `upld-${idx}-${Math.random().toString(36).substr(2, 4)}`,
          url,
          title,
          visitTime: String(visitTimeRaw),
          visitCount: Number(item.visitCount || item.visit_count || 1),
          typedCount: item.typedCount || item.typed_count ? Number(item.typedCount || item.typed_count) : undefined,
        };
      });
    } catch (e) {
      throw new Error(`Invalid JSON syntax. Ensure file is a standard list of history nodes. (${(e as Error).message})`);
    }
  } else {
    // Simple robust CSV parser
    try {
      const lines = rawText.split(/\r?\n/);
      if (lines.length < 2) return [];

      // Find headers
      const headers = lines[0].split(",").map(h => h.trim().replace(/^["']|["']$/g, "").toLowerCase());
      
      const urlIdx = headers.findIndex(h => h === "url" || h === "address" || h === "link");
      const titleIdx = headers.findIndex(h => h === "title" || h === "name" || h === "page title");
      const rtimeIdx = headers.findIndex(h => h === "visittime" || h === "visit_time" || h === "time" || h === "timestamp" || h === "date");

      if (urlIdx === -1) {
        throw new Error("Could not find a 'url' column inside your CSV header row.");
      }

      const items: BrowserHistoryItem[] = [];

      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        // Smart split of CSV ignoring commas inside quotes
        const columns: string[] = [];
        let inQuotes = false;
        let currentField = "";
        
        for (let charIdx = 0; charIdx < line.length; charIdx++) {
          const char = line[charIdx];
          if (char === '"' || char === "'") {
            inQuotes = !inQuotes;
          } else if (char === "," && !inQuotes) {
            columns.push(currentField.trim().replace(/^["']|["']$/g, ""));
            currentField = "";
          } else {
            currentField += char;
          }
        }
        columns.push(currentField.trim().replace(/^["']|["']$/g, ""));

        if (columns.length === 0 || !columns[urlIdx]) continue;

        const url = columns[urlIdx];
        const title = titleIdx !== -1 && columns[titleIdx] ? columns[titleIdx] : url;
        let finalTime = new Date().toISOString();

        if (rtimeIdx !== -1 && columns[rtimeIdx]) {
          const rawVTime = columns[rtimeIdx];
          // Try to convert to Date
          try {
            const parsedD = new Date(rawVTime);
            if (!isNaN(parsedD.getTime())) {
              finalTime = parsedD.toISOString();
            } else if (/^\d+$/.test(rawVTime)) {
              // try processing Unix epoch number check
              const epochNum = parseInt(rawVTime, 10);
              if (epochNum > 10000000000000) {
                // webkit microsecond
                finalTime = new Date(Math.round(epochNum / 1000) - 11644473600000).toISOString();
              } else if (epochNum > 100000000000) {
                finalTime = new Date(epochNum).toISOString();
              } else {
                finalTime = new Date(epochNum * 1000).toISOString();
              }
            }
          } catch {}
        }

        items.push({
          id: `upld-csv-${i}-${Math.random().toString(36).substr(2, 4)}`,
          url,
          title,
          visitTime: finalTime,
          visitCount: 1
        });
      }

      return items;
    } catch (e) {
      throw new Error(`CSV parser error: ${(e as Error).message}`);
    }
  }
}
