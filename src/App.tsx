/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useEffect, useRef } from "react";
import {
  FileText,
  AlertTriangle,
  Search,
  Upload,
  Layers,
  Clock,
  ChevronRight,
  ShieldCheck,
  Download,
  Terminal,
  Cpu,
  Bookmark,
  ExternalLink,
  RefreshCw,
  Send,
  HelpCircle,
  Database,
  Filter,
  CheckCircle2,
  Calendar,
  AlertOctagon,
  Eye,
  Activity,
  User,
  Info
} from "lucide-react";
import { INSIDER_THREAT_CASE, PHISHING_BREACH_CASE, STANDARD_BASELINE_CASE } from "./sampleData";
import {
  analyzeBrowserHistory,
  reconstructSessions,
  gatherForensicMetrics,
  parseBrowserHistoryText,
} from "./forensicsEngine";
import { BrowserHistoryItem, AnalyzedRecord, UserSession, ForensicMetrics, AiInvestigationResponse } from "./types";

export default function App() {
  // Navigation internal tab
  const [activeTab, setActiveTab] = useState<"dashboard" | "timeline" | "raw" | "guides">("dashboard");

  // Filter conditions for current logs
  const [searchFilter, setSearchFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState<"ALL" | "Critical" | "High" | "Medium" | "Low">("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");

  // Active dataset management
  const [currentScenario, setCurrentScenario] = useState<"insider" | "phishing" | "baseline" | "custom">("insider");
  const [rawHistory, setRawHistory] = useState<BrowserHistoryItem[]>(INSIDER_THREAT_CASE);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Parse items
  const analyzedRecords = useMemo(() => {
    return analyzeBrowserHistory(rawHistory);
  }, [rawHistory]);

  const sessions = useMemo(() => {
    return reconstructSessions(analyzedRecords);
  }, [analyzedRecords]);

  const metrics: ForensicMetrics = useMemo(() => {
    return gatherForensicMetrics(analyzedRecords);
  }, [analyzedRecords]);

  // Selected item / session inside Inspector panel
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  // Track selected detailed trace object
  const selectedRecord = useMemo(() => {
    if (!selectedRecordId) return null;
    return analyzedRecords.find(r => r.id === selectedRecordId) || null;
  }, [selectedRecordId, analyzedRecords]);

  const selectedSession = useMemo(() => {
    if (!selectedSessionId) return sessions[0] || null;
    return sessions.find(s => s.id === selectedSessionId) || null;
  }, [selectedSessionId, sessions]);

  // Set default selection on load
  useEffect(() => {
    if (analyzedRecords.length > 0 && !selectedRecordId) {
      // Pick first flagged or highest-threat record
      const dangerous = analyzedRecords.find(r => r.flags.length > 0);
      if (dangerous) {
        setSelectedRecordId(dangerous.id);
      } else {
        setSelectedRecordId(analyzedRecords[0].id);
      }
    }
  }, [analyzedRecords]);

  // Drag and drop state
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Gemini investigation state
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [aiReport, setAiReport] = useState<AiInvestigationResponse | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  // Chat/QA custom search queries
  const [customQuestion, setCustomQuestion] = useState("");
  const [qaHistory, setQaHistory] = useState<Array<{ q: string; a: string }>>([]);
  const [isAsking, setIsAsking] = useState(false);

  // Unique categories list for filters
  const categoriesList = useMemo(() => {
    const set = new Set<string>();
    analyzedRecords.forEach(r => set.add(r.category));
    return Array.from(set);
  }, [analyzedRecords]);

  // Trigger loading state for dynamic switch scenarios
  const handleLoadScenario = (type: "insider" | "phishing" | "baseline") => {
    setErrorMessage(null);
    setAiReport(null);
    setQaHistory([]);
    setSelectedRecordId(null);
    setSelectedSessionId(null);
    
    if (type === "insider") {
      setRawHistory(INSIDER_THREAT_CASE);
      setCurrentScenario("insider");
      setSuccessMessage("Loaded default 'Insider Threat' suspect case log.");
    } else if (type === "phishing") {
      setRawHistory(PHISHING_BREACH_CASE);
      setCurrentScenario("phishing");
      setSuccessMessage("Loaded default 'Phishing Compromise' event log.");
    } else {
      setRawHistory(STANDARD_BASELINE_CASE);
      setCurrentScenario("baseline");
      setSuccessMessage("Loaded standard 'Development Baseline' history baseline.");
    }

    setTimeout(() => setSuccessMessage(null), 3500);
  };

  // Upload logs trigger
  const handleFileUploadRaw = (text: string, name: string) => {
    try {
      setErrorMessage(null);
      const parsed = parseBrowserHistoryText(text, "auto");
      
      if (parsed.length === 0) {
        throw new Error("No browsing record events extracted from source format.");
      }

      setRawHistory(parsed);
      setCurrentScenario("custom");
      setAiReport(null);
      setQaHistory([]);
      setSelectedRecordId(parsed[0]?.id || null);
      setSelectedSessionId(null);
      setSuccessMessage(`Successfully uploaded and analyzed ${parsed.length} items from ${name}.`);
      setTimeout(() => setSuccessMessage(null), 4000);
    } catch (e) {
      setErrorMessage((e as Error).message);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        handleFileUploadRaw(text, file.name);
      };
      reader.readAsText(file);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        handleFileUploadRaw(text, file.name);
      };
      reader.readAsText(file);
    }
  };

  // Run Gemini investigative summary
  const runGeminiAnalysis = async (focusOption?: string) => {
    setIsInvestigating(true);
    setReportError(null);
    
    // Choose selected session records or top 40 records to keep prompt context pristine
    const targetSessionRecords = selectedSession ? selectedSession.records : analyzedRecords.slice(0, 45);
    const sessionContext = selectedSession 
      ? `Reconstructed session covering ${selectedSession.startTime} to ${selectedSession.endTime} with duration of ${selectedSession.durationMinutes} minutes.`
      : "Full uploaded historical time window trace.";

    try {
      const res = await fetch("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          records: targetSessionRecords,
          sessionContext,
          customQuestion: focusOption || "Generate detailed investigative forensic audit summary"
        }),
      });

      if (!res.ok) {
        const errObj = await res.json();
        throw new Error(errObj.error || errObj.details || "API server generated an unexpected fault.");
      }

      const reportData: AiInvestigationResponse = await res.json();
      setAiReport(reportData);
    } catch (e: any) {
      setReportError(e.message || "Failed to establish a valid secure pipeline to Gemini AI. Confirm API Key set up.");
    } finally {
      setIsInvestigating(false);
    }
  };

  // Interactive investigator console chat query
  const handleAskQuestion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customQuestion.trim() || isAsking) return;

    const query = customQuestion.trim();
    setCustomQuestion("");
    setIsAsking(true);

    try {
      // Append question to QA history first
      setQaHistory(prev => [...prev, { q: query, a: "Consulting AI cognitive models in Sandbox..." }]);

      const targetSessionRecords = selectedSession ? selectedSession.records : analyzedRecords.slice(0, 45);
      const res = await fetch("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          records: targetSessionRecords,
          sessionContext: `This is a specific query regarding historical trace events. The investigator asks: "${query}"`,
          customQuestion: `Respond DIRECTLY and thoroughly to this question. Do not hide information: "${query}". Format output under normal schema structure and focus deeply on addressing this query inside the 'hypothesis' or 'intentSynthesis' fields.`
        }),
      });

      if (!res.ok) {
        throw new Error("Server failed to respond correctly.");
      }

      const data: AiInvestigationResponse = await res.json();
      const rawAnswer = data.hypothesis || data.intentSynthesis;

      setQaHistory(prev => {
        const next = [...prev];
        if (next.length > 0) {
          next[next.length - 1].a = rawAnswer;
        }
        return next;
      });

    } catch (err) {
      setQaHistory(prev => {
        const next = [...prev];
        if (next.length > 0) {
          next[next.length - 1].a = "Error communicating with AI router. Please try verifying key parameters.";
        }
        return next;
      });
    } finally {
      setIsAsking(false);
    }
  };

  // Filtered list of raw items
  const filteredRecords = useMemo(() => {
    return analyzedRecords.filter((rec) => {
      const matchesSearch =
        rec.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
        rec.url.toLowerCase().includes(searchFilter.toLowerCase()) ||
        rec.domain.toLowerCase().includes(searchFilter.toLowerCase()) ||
        (rec.searchQuery && rec.searchQuery.toLowerCase().includes(searchFilter.toLowerCase()));

      const hasRisk = rec.flags.some(f => f.riskLevel === riskFilter);
      const matchesRisk = riskFilter === "ALL" || hasRisk;

      const matchesCategory = categoryFilter === "ALL" || rec.category === categoryFilter;

      return matchesSearch && matchesRisk && matchesCategory;
    });
  }, [analyzedRecords, searchFilter, riskFilter, categoryFilter]);

  return (
    <div id="app" className="flex h-screen w-full bg-slate-950 font-sans text-slate-200 overflow-hidden">
      
      {/* SIDEBAR NAVIGATION - THEME: PROFESSIONAL POLISH */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-blue-600 rounded flex items-center justify-center text-white font-black tracking-widest shadow-lg shadow-blue-500/20">
              BF
            </div>
            <div>
              <span className="font-bold tracking-tight text-white block">Browser Forensics</span>
              <span className="text-[10px] text-blue-400 font-mono tracking-widest uppercase">Console v4.2</span>
            </div>
          </div>
        </div>

        {/* Dynamic suspect scenario selector inside Sidebar */}
        <div className="p-4 border-b border-slate-800 bg-slate-950/40">
          <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">
            Investigation Targets
          </label>
          <div className="space-y-1.5 text-xs">
            <button
              onClick={() => handleLoadScenario("insider")}
              className={`w-full text-left px-3 py-2 rounded flex items-center gap-2 transition-all ${
                currentScenario === "insider"
                  ? "bg-slate-800 text-amber-400 font-medium border border-amber-900/30"
                  : "hover:bg-slate-800 text-slate-300"
              }`}
            >
              <UsersIcon className="w-3.5 h-3.5" />
              <span>Suspect Case: Insider Threat</span>
            </button>
            <button
              onClick={() => handleLoadScenario("phishing")}
              className={`w-full text-left px-3 py-2 rounded flex items-center gap-2 transition-all ${
                currentScenario === "phishing"
                  ? "bg-slate-800 text-rose-400 font-medium border border-rose-900/30"
                  : "hover:bg-slate-800 text-slate-300"
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Suspect Case: Phishing Hack</span>
            </button>
            <button
              onClick={() => handleLoadScenario("baseline")}
              className={`w-full text-left px-3 py-2 rounded flex items-center gap-2 transition-all ${
                currentScenario === "baseline"
                  ? "bg-slate-800 text-emerald-400 font-medium border border-emerald-950/30"
                  : "hover:bg-slate-800 text-slate-300"
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Norm baseline: Developer</span>
            </button>
          </div>
        </div>

        {/* Primary Tab options */}
        <nav className="flex-1 p-4 space-y-1">
          <div className="text-[10px] font-bold uppercase text-slate-500 px-3 py-2 tracking-widest">
            Main Console
          </div>
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`w-full flex items-center justify-between px-3 py-2 text-sm rounded transition-all ${
              activeTab === "dashboard"
                ? "bg-slate-800 text-blue-400 border-l-2 border-blue-500"
                : "text-slate-400 hover:text-white hover:bg-slate-800/55"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Activity className="w-4 h-4" />
              <span>Session Workspace</span>
            </div>
            {sessions.length > 0 && (
              <span className="bg-slate-950 text-slate-400 py-0.5 px-2 text-[10px] font-mono rounded-full">
                {sessions.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("timeline")}
            className={`w-full flex items-center justify-between px-3 py-2 text-sm rounded transition-all ${
              activeTab === "timeline"
                ? "bg-slate-800 text-blue-400 border-l-2 border-blue-500"
                : "text-slate-400 hover:text-white hover:bg-slate-800/55"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Clock className="w-4 h-4" />
              <span>Timeline Reconstruction</span>
            </div>
          </button>

          <button
            onClick={() => setActiveTab("raw")}
            className={`w-full flex items-center justify-between px-3 py-2 text-sm rounded transition-all ${
              activeTab === "raw"
                ? "bg-slate-800 text-blue-400 border-l-2 border-blue-500"
                : "text-slate-400 hover:text-white hover:bg-slate-800/55"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Database className="w-4 h-4" />
              <span>Suspicious Event Log</span>
            </div>
            {metrics.criticalAlertCount + metrics.highAlertCount > 0 && (
              <span className="bg-rose-950/80 text-rose-400 py-0.5 px-1.5 text-[10px] font-bold rounded">
                {metrics.criticalAlertCount + metrics.highAlertCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("guides")}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-sm rounded transition-all ${
              activeTab === "guides"
                ? "bg-slate-800 text-blue-400 border-l-2 border-blue-500"
                : "text-slate-400 hover:text-white hover:bg-slate-800/55"
            }`}
          >
            <HelpCircle className="w-4 h-4" />
            <span>Forensic Playbook</span>
          </button>
        </nav>

        {/* Sidebar Info Footer */}
        <div className="p-4 bg-slate-950/60 border-t border-slate-800">
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 font-mono">
              Detection Engine Active
            </span>
          </div>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Automatic heuristic scanner and trace state parser run off browser artifact structures. Correctly map and isolate evidence timelines.
          </p>
        </div>
      </aside>

      {/* MAIN VIEW CONTROLLER */}
      <main className="flex-1 flex flex-col overflow-hidden">
        
        {/* TOP STATUS CONTROL BAR */}
        <header className="h-16 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between px-8 z-10">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold text-white tracking-tight">
                User Activity Reconstruction
              </h1>
              {currentScenario !== "custom" && (
                <span className="bg-slate-800 text-slate-300 text-[10px] font-mono font-medium px-2 py-0.5 rounded border border-slate-700">
                  Demo Active
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Interactive sandbox workspace for analyzing browser logs and generating clinical investigative reports.
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Real File Upload Section */}
            <div className="relative">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileInputChange}
                accept=".json,.csv"
                className="hidden"
                id="raw-history-file-picker"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 border border-slate-700 rounded transition-all flex items-center gap-2"
              >
                <Upload className="w-3.5 h-3.5" />
                Upload History Log
              </button>
            </div>

            <button
              onClick={() => runGeminiAnalysis()}
              disabled={isInvestigating}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-xs font-bold text-white rounded shadow-lg shadow-blue-900/40 transition-all flex items-center gap-2 disabled:bg-slate-700 disabled:cursor-not-allowed"
            >
              {isInvestigating ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Analyzing Trace...
                </>
              ) : (
                <>
                  <Cpu className="w-3.5 h-3.5" />
                  Run Gemini AI Deep Scan
                </>
              )}
            </button>
          </div>
        </header>

        {/* METRICS CARD DISPLAY GRID */}
        <section className="grid grid-cols-4 gap-4 p-6 bg-slate-950 border-b border-slate-900">
          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800/60 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">
                Artifact Log Count
              </div>
              <div className="text-2xl font-light text-white font-mono">{metrics.totalRecords}</div>
              <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <Layers className="w-3 h-3 text-blue-400" />
                <span>Across {metrics.uniqueDomainsCount} unique domains</span>
              </div>
            </div>
            <div className="w-10 h-10 bg-slate-800/40 rounded-full flex items-center justify-center border border-slate-700/40">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
          </div>

          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800/60 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-bold text-rose-500 uppercase tracking-widest mb-1">
                Critical Indicators
              </div>
              <div className="text-2xl font-light text-rose-400 font-mono">
                {metrics.criticalAlertCount}
              </div>
              <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <AlertOctagon className="w-3 h-3 text-rose-400" />
                <span>High-Risk anomalies detected</span>
              </div>
            </div>
            <div className={`w-10 h-10 rounded-full flex items-center justify-center border ${
              metrics.criticalAlertCount > 0 ? "bg-rose-950/20 border-rose-900/60" : "bg-slate-800/40 border-slate-700/40"
            }`}>
              <AlertOctagon className={`w-5 h-5 ${metrics.criticalAlertCount > 0 ? "text-rose-400 animate-pulse" : "text-slate-500"}`} />
            </div>
          </div>

          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800/60 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-bold text-amber-500 uppercase tracking-widest mb-1">
                Aggregated Threat Index
              </div>
              <div className="text-2xl font-bold font-mono text-amber-400">
                {metrics.threatMultiplier}%
              </div>
              <div className="text-[10px] text-slate-400 mt-1">
                Forensic severity score
              </div>
            </div>
            <div className="w-10 h-10 bg-slate-800/40 rounded-full flex items-center justify-center border border-slate-700/40">
              <Activity className="w-5 h-5 text-amber-400" />
            </div>
          </div>

          <div className="bg-slate-100/5 p-4 rounded-lg border border-slate-800/60 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">
                Off-Hours Activity Ratio
              </div>
              <div className="text-2xl font-light text-white font-mono">
                {Math.round(metrics.lateNightVisitRatio * 100)}%
              </div>
              <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <Clock className="w-3 h-3 text-violet-400" />
                <span>Done during off-work window</span>
              </div>
            </div>
            <div className="w-10 h-10 bg-slate-800/40 rounded-full flex items-center justify-center border border-slate-700/40">
              <Clock className="w-5 h-5 text-violet-400" />
            </div>
          </div>
        </section>

        {/* FEEDBACK SYSTEM MESSAGES */}
        {errorMessage && (
          <div className="mx-6 mt-4 p-3 bg-rose-950/40 border border-rose-900/60 text-rose-200 text-xs rounded-lg flex items-center gap-3 animate-fadeIn">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <div>
              <span className="font-bold">Error parsing uploaded archive:</span> {errorMessage}
            </div>
          </div>
        )}

        {successMessage && (
          <div className="mx-6 mt-4 p-3 bg-emerald-950/40 border border-emerald-900/60 text-emerald-200 text-xs rounded-lg flex items-center gap-3 animate-fadeIn">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>{successMessage}</div>
          </div>
        )}

        {/* DYNAMIC TAB COMPONENT PANELS */}
        <section className="flex-1 px-6 pb-6 pt-4 flex gap-6 overflow-hidden bg-slate-950">
          
          {/* LEFT 2/3 COLUMN: VIEW SHELL */}
          <div className="flex-[2] bg-slate-900 border border-slate-800/80 rounded-lg overflow-hidden flex flex-col">
            
            {/* SUB HEADER TABS AND CONTROLS */}
            <div className="px-5 py-3 bg-slate-800/35 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-slate-400" />
                <span className="text-xs font-mono text-slate-300 font-bold uppercase tracking-wider">
                  {activeTab === "dashboard" && "Workspace Chronological Sesssions"}
                  {activeTab === "timeline" && "Forensic Reconstruction Chronology"}
                  {activeTab === "raw" && "Audit Registry Master Log"}
                  {activeTab === "guides" && "Suspicious Incident Investigation Playbook"}
                </span>
              </div>

              {/* CSV Upload / Quick Paste Help box in raw logs */}
              {activeTab === "raw" && (
                <div className="flex items-center gap-3 text-xs text-slate-400">
                  <div className="flex items-center gap-2 bg-slate-950 px-2 py-1 rounded">
                    <Filter className="w-3.5 h-3.5 text-blue-500" />
                    <span>Risk:</span>
                    <select
                      value={riskFilter}
                      onChange={(e) => setRiskFilter(e.target.value as any)}
                      className="bg-transparent text-slate-300 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
                    >
                      <option value="ALL">ALL RISK LEVELS</option>
                      <option value="Critical">Critical Only</option>
                      <option value="High">High Only</option>
                      <option value="Medium">Medium Only</option>
                      <option value="Low">Low Only</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-2 bg-slate-950 px-2 py-1 rounded">
                    <span>Category:</span>
                    <select
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      className="bg-transparent text-slate-300 font-mono text-xs focus:outline-none max-w-[150px]"
                    >
                      <option value="ALL">ALL CATEGORIES</option>
                      {categoriesList.map((cat, idx) => (
                        <option key={idx} value={cat}>{cat}</option>
                      ))}
                    </select>
                  </div>
                </div>
              )}
            </div>

            {/* TAB CONTAINER BODY */}
            <div className="flex-1 overflow-y-auto">
              
              {/* 1. SESSION RECONSTRUCTION WORKSPACE */}
              {activeTab === "dashboard" && (
                <div className="p-5 space-y-4">
                  <div className="bg-slate-950/40 p-4 rounded-lg border border-slate-800 text-xs space-y-2">
                    <div className="flex items-center gap-2 text-blue-400 font-bold">
                      <Layers className="w-4 h-4" />
                      <h4>Activity Reconstruction Explanation</h4>
                    </div>
                    <p className="text-slate-400 leading-relaxed">
                      To prevent investigator clutter, we track gaps exceeding <strong className="text-white">40 minutes</strong> and assemble continuous browser logs into <strong>Activity Sessions</strong>. This patterns specific, focused user operations such as exfil bursts, research focus, or standard workflow, mimicking premium endpoint detection capabilities.
                    </p>
                  </div>

                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                    Identified Activity Sessions ({sessions.length})
                  </h3>

                  {sessions.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 text-xs italic">
                      No sessions determined. Try uploading a different archive.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {sessions.map((sess) => {
                        const isSelected = selectedSession?.id === sess.id;
                        const scoreColor = 
                          sess.aggregateThreatScore >= 70 ? "text-rose-400 bg-rose-950/40 border-rose-900/40" :
                          sess.aggregateThreatScore >= 35 ? "text-amber-400 bg-amber-950/40 border-amber-900/40" :
                          "text-emerald-400 bg-emerald-950/30 border-emerald-900/30";

                        return (
                          <div
                            key={sess.id}
                            onClick={() => setSelectedSessionId(sess.id)}
                            className={`p-4 rounded-lg border cursor-pointer transition-all ${
                              isSelected
                                ? "bg-slate-800/80 border-blue-500/85 shadow-md"
                                : "bg-slate-900/50 border-slate-800/80 hover:bg-slate-850"
                            }`}
                          >
                            <div className="flex items-start justify-between">
                              <div className="space-y-1">
                                <span className={`inline-block text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${scoreColor}`}>
                                  Threat Rating: {sess.aggregateThreatScore}/100
                                </span>
                                <h4 className="text-sm font-semibold text-white mt-1.5 flex items-center gap-1.5 leading-relaxed">
                                  {sess.primaryActivity}
                                </h4>
                              </div>
                              <div className="text-right text-[11px] text-slate-500 space-y-0.5 font-mono">
                                <div className="flex items-center gap-1 justify-end">
                                  <Clock className="w-3 h-3" />
                                  <span>{sess.durationMinutes} mins active</span>
                                </div>
                                <div>{sess.recordCount} records</div>
                              </div>
                            </div>

                            <div className="mt-4 flex items-center justify-between text-xs text-slate-400 pt-3 border-t border-slate-800/50">
                              <div className="flex items-center gap-3">
                                <span className="flex items-center gap-1">
                                  <Calendar className="w-3.5 h-3.5 text-slate-500" />
                                  <span>{new Date(sess.startTime).toLocaleDateString()}</span>
                                </span>
                                <span>•</span>
                                <span className="font-mono text-slate-500">
                                  {new Date(sess.startTime).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} - {new Date(sess.endTime).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                                </span>
                              </div>

                              <div className="flex items-center gap-1 text-blue-400 font-bold">
                                <span>Inspect Session Details</span>
                                <ChevronRight className="w-3.5 h-3.5" />
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* 2. TIMELINE RECONSTRUCTION */}
              {activeTab === "timeline" && (
                <div className="p-5">
                  <div className="relative border-l-2 border-slate-800 ml-4 pl-6 space-y-6">
                    {analyzedRecords.length === 0 ? (
                      <div className="text-center text-slate-500 italic py-10 text-xs">
                        No events present inside current buffer.
                      </div>
                    ) : (
                      analyzedRecords.map((rec, i) => {
                        const hasFlags = rec.flags.length > 0;
                        const date = new Date(rec.visitTime);
                        const hour = date.getHours();
                        const isLateNight = hour >= 0 && hour < 5;

                        return (
                          <div key={rec.id || i} className="relative group">
                            {/* Visual Timeline Node pointer */}
                            <span className={`absolute -left-9 top-1.5 w-4 h-4 rounded-full border-2 ${
                              hasFlags 
                                ? rec.flags.some(f => f.riskLevel === "Critical" || f.riskLevel === "High")
                                  ? "bg-rose-500 border-rose-950 animate-ping"
                                  : "bg-amber-500 border-amber-950" 
                                : isLateNight 
                                  ? "bg-violet-500 border-violet-950"
                                  : "bg-slate-700 border-slate-900"
                            }`}></span>
                            
                            {/* Content Card */}
                            <div className={`p-4 rounded-lg border transition-all ${
                              selectedRecordId === rec.id 
                                ? "bg-slate-850 border-blue-500/80" 
                                : "bg-slate-900/40 border-slate-800/80 hover:bg-slate-800/40"
                            }`} onClick={() => setSelectedRecordId(rec.id)}>
                              
                              <div className="flex justify-between items-start gap-4 mb-2">
                                <div className="space-y-0.5">
                                  <span className="text-[10px] text-slate-500 font-mono tracking-tight font-semibold">
                                    {date.toLocaleString()}
                                  </span>
                                  <h4 className="text-sm font-semibold text-slate-100 group-hover:text-blue-400 transition-colors">
                                    {rec.title}
                                  </h4>
                                </div>
                                <span className="text-xs bg-slate-950 px-2 py-0.5 rounded text-slate-400 font-mono select-none">
                                  {rec.domain}
                                </span>
                              </div>

                              <p className="text-xs text-slate-400 truncate font-mono">
                                {rec.url}
                              </p>

                              {rec.searchQuery && (
                                <div className="mt-2 text-xs bg-slate-950/60 p-2 rounded border border-slate-800 flex items-center gap-2">
                                  <Search className="w-3.5 h-3.5 text-blue-400" />
                                  <span className="text-slate-300 italic">Google Query:</span>
                                  <strong className="text-slate-200 font-mono">"{rec.searchQuery}"</strong>
                                </div>
                              )}

                              {/* Flag markers inside list item */}
                              {hasFlags && (
                                <div className="mt-2.5 flex flex-wrap gap-1.5">
                                  {rec.flags.map((flg, idx) => (
                                    <span
                                      key={idx}
                                      className={`text-[10px] font-mono px-2 py-0.5 bg-rose-950/40 border border-rose-900/30 rounded font-bold uppercase ${
                                        flg.riskLevel === "Critical" ? "text-rose-400 border-rose-800" : "text-amber-400 border-amber-800"
                                      }`}
                                    >
                                      [{flg.category}] {flg.ruleName}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              )}

              {/* 3. SUSPICIOUS EVENT LOG (FILTERABLE GRID) */}
              {activeTab === "raw" && (
                <div className="overflow-x-auto">
                  
                  {/* SEARCH SEARCH INPUT BAR */}
                  <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
                    <Search className="w-4 h-4 text-slate-500 ml-2" />
                    <input
                      type="text"
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      placeholder="Search across history logs by URL, title keyword, domain or google search query..."
                      className="bg-transparent text-slate-100 placeholder-slate-500 text-xs focus:outline-none w-full py-1.5"
                    />
                    {searchFilter && (
                      <button
                        onClick={() => setSearchFilter("")}
                        className="text-[10px] uppercase font-bold text-slate-500 hover:text-white px-2"
                      >
                        Clear
                      </button>
                    )}
                  </div>

                  <table className="w-full text-left text-xs whitespace-nowrap">
                    <thead>
                      <tr className="bg-slate-950/60 text-slate-500 font-bold uppercase tracking-widest border-b border-slate-800 text-[10px]">
                        <th className="py-3.5 px-5">TIMESTAMP</th>
                        <th className="py-3.5 px-4">DOMAIN / ADDRESS</th>
                        <th className="py-3.5 px-4">HEURISTIC ACTIVITY</th>
                        <th className="py-3.5 px-4 text-center">RISK WEIGHT</th>
                        <th className="py-3.5 px-4">THREAT LEVEL</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {filteredRecords.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-10 text-center text-slate-500 italic">
                            No records matching selected security filters.
                          </td>
                        </tr>
                      ) : (
                        filteredRecords.map((rec) => {
                          const hasFlags = rec.flags.length > 0;
                          const timestamp = new Date(rec.visitTime).toLocaleString();

                          return (
                            <tr
                              key={rec.id}
                              onClick={() => setSelectedRecordId(rec.id)}
                              className={`cursor-pointer transition-all ${
                                selectedRecordId === rec.id
                                  ? "bg-slate-800/80"
                                  : "hover:bg-slate-850/50"
                              }`}
                            >
                              <td className="py-3 px-5 font-mono text-slate-400">
                                {timestamp}
                              </td>
                              <td className="py-3 px-4 max-w-[200px] truncate">
                                <div className="font-semibold text-slate-200">{rec.domain}</div>
                                <div className="text-[10px] text-slate-500 font-mono truncate">{rec.url}</div>
                              </td>
                              <td className="py-3 px-4 max-w-[320px] truncate">
                                <div className="text-slate-300 font-medium truncate">{rec.title}</div>
                                {rec.searchQuery && (
                                  <div className="text-[10px] text-blue-400 italic font-mono truncate">
                                    Query: "{rec.searchQuery}"
                                  </div>
                                )}
                              </td>
                              <td className="py-3 px-4 text-center select-none">
                                {hasFlags ? (
                                  <span className={`inline-block px-2.5 py-1 text-[9px] font-extrabold rounded-full ${
                                    rec.flags.some(f => f.riskLevel === "Critical")
                                      ? "bg-rose-950/65 text-rose-400 border border-rose-800/60"
                                      : rec.flags.some(f => f.riskLevel === "High")
                                        ? "bg-amber-950/65 text-amber-400 border border-amber-900/60"
                                        : "bg-blue-950/65 text-blue-400 border border-blue-900/60"
                                  }`}>
                                    {rec.flags[0].category.toUpperCase()}
                                  </span>
                                ) : (
                                  <span className="text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-[10px] font-mono">
                                    SAFE ACCESS
                                  </span>
                                )}
                              </td>
                              <td className="py-3 px-4">
                                <div className="flex items-center gap-2">
                                  <div className="w-12 bg-slate-950 rounded-full h-1.5 overflow-hidden">
                                    <div
                                      className={`h-full rounded-full ${
                                        rec.threatScore >= 70 ? "bg-rose-500" :
                                        rec.threatScore >= 35 ? "bg-amber-500" : "bg-emerald-500"
                                      }`}
                                      style={{ width: `${rec.threatScore}%` }}
                                    ></div>
                                  </div>
                                  <span className="font-mono font-bold text-slate-300 block text-[11px]">
                                    {rec.threatScore}%
                                  </span>
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {/* 4. CLINICAL INVESTIGATION PLAYBOOK */}
              {activeTab === "guides" && (
                <div className="p-6 text-xs text-slate-300 space-y-5 leading-relaxed">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                    Browser Forensics Investigations Playbook & Standards
                  </h3>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-950/40 p-4 rounded-lg border border-slate-800">
                      <h4 className="font-bold text-blue-400 mb-2 uppercase tracking-wide">
                        1. Data Exfiltration Identification
                      </h4>
                      <p className="text-slate-400">
                        Insiders routinely attempt to move corporate secrets onto personal channels. Signs to target:
                      </p>
                      <ul className="list-disc pl-4 mt-2 space-y-1 text-slate-400">
                        <li>Usage of single-part or split rar compression sites.</li>
                        <li>Connection to unapproved cloud endpoints (Mega, GoFile).</li>
                        <li>Search terms probing gateway EDR rules or DLP transfer limitations.</li>
                      </ul>
                    </div>

                    <div className="bg-slate-950/40 p-4 rounded-lg border border-slate-800">
                      <h4 className="font-bold text-amber-400 mb-2 uppercase tracking-wide">
                        2. Defensive Evasion Techniques
                      </h4>
                      <p className="text-slate-400">
                        Informed suspects frequently clean up their workspace tracing footprints using secure erasure tools:
                      </p>
                      <ul className="list-disc pl-4 mt-2 space-y-1 text-slate-400">
                        <li>Visits or packages involving BleachBit, DBAN, Eraser.</li>
                        <li>PowerShell scripts that loop and wipe Windows Event Log streams.</li>
                        <li>Chrome parameters tweaking disk caching rules.</li>
                      </ul>
                    </div>

                    <div className="bg-slate-950/40 p-4 rounded-lg border border-slate-800">
                      <h4 className="font-bold text-rose-400 mb-2 uppercase tracking-wide">
                        3. Typosquatting and Phishing Detection
                      </h4>
                      <p className="text-slate-400">
                        Legitimate accounts are frequently subverted by high-fidelity phishing clones. Analyze:
                      </p>
                      <ul className="list-disc pl-4 mt-2 space-y-1 text-slate-400">
                        <li>Subtle spelling changes: <span className="text-slate-200 font-mono">well-fargo</span> instead of <span className="text-slate-200 font-mono">wellsfargo</span>.</li>
                        <li>Lack of parent redirecting referrers or unexpected login portals.</li>
                        <li>Subsequent visits searching for "suspicious withdrawals" or "mfa bypass fixes".</li>
                      </ul>
                    </div>

                    <div className="bg-slate-950/40 p-4 rounded-lg border border-slate-800">
                      <h4 className="font-bold text-emerald-400 mb-2 uppercase tracking-wide">
                        4. Establishing Norms and Baselines
                      </h4>
                      <p className="text-slate-400">
                        SecOps engineers search extensively for code fragments on StackOverflow, Github, and chat systems every day.
                      </p>
                      <ul className="list-disc pl-4 mt-2 space-y-1 text-slate-400">
                        <li>Evaluate normal technical keywords compared to targeted intellectual research queries.</li>
                        <li>Distinguish benign StackOverflow sessions from sequential job applications paired with code exfiltration.</li>
                      </ul>
                    </div>
                  </div>

                  <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-2 mt-2">
                    <h4 className="font-bold text-white flex items-center gap-2">
                      <Info className="w-4 h-4 text-blue-400" />
                      About this Browser Forensic Application
                    </h4>
                    <p className="text-slate-400">
                      This system implements high fidelity client-side heuristic engines in pure typescript, rendering risk assessments instantly. By incorporating Gemini's cognitive text reasoning capacity, it automatically synthesizes advanced human investigator hypothesis reports, bridging raw events with structured threat insights.
                    </p>
                  </div>
                </div>
              )}

            </div>
          </div>

          {/* RIGHT COLUMN: INSPECTOR PANEL & GEMINI INSIGHTS */}
          <div className="flex-1 bg-slate-900 border border-slate-800/80 rounded-lg flex flex-col overflow-hidden">
            
            <div className="px-5 py-3.5 bg-slate-800/40 border-b border-slate-800">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Terminal className="text-blue-500 w-4 h-4" />
                Investigative Forensic Inspector
              </h3>
            </div>

            {/* INSPECTOR PANEL scroll container */}
            <div className="flex-1 p-5 overflow-y-auto space-y-5">
              
              {/* CURRENT ACTIVE TARGET INFO CONTAINER */}
              <div className="bg-slate-950/40 p-3.5 rounded-lg border border-slate-800/80 space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] font-bold text-slate-500 uppercase font-mono tracking-wide">
                    {selectedSession ? "ACTIVE CHRONOLOGICAL BLOCK" : "SELECTED EVENT REGISTRY"}
                  </span>
                  <span className="text-[9px] bg-slate-800 text-slate-400 font-mono px-2 py-0.5 rounded">
                    {selectedSession ? selectedSession.id.toUpperCase() : "SINGLE ITEM"}
                  </span>
                </div>

                {selectedSession ? (
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-white leading-relaxed">
                      {selectedSession.primaryActivity}
                    </h4>
                    <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400 font-mono mt-1">
                      <div>• Time duration: <strong className="text-slate-200">{selectedSession.durationMinutes}m</strong></div>
                      <div>• Alerts: <strong className="text-rose-400">{selectedSession.flagCount}</strong></div>
                      <div>• Records: <strong className="text-slate-200">{selectedSession.recordCount}</strong></div>
                      <div>• Score index: <strong className="text-amber-400">{selectedSession.aggregateThreatScore}%</strong></div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">Select an activity or event to view deep telemetry.</p>
                )}
              </div>

              {/* INTEGRATED GEMINI ANALYSIS TAB */}
              <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/30 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-1 rounded bg-blue-600/30 border border-blue-500/20">
                      <Cpu className="w-4 h-4 text-blue-400" />
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-white">Gemini Forensic Synthesis</h4>
                      <p className="text-[10px] text-slate-500">AI cognitive incident timeline audit</p>
                    </div>
                  </div>

                  {!aiReport && (
                    <button
                      onClick={() => runGeminiAnalysis()}
                      disabled={isInvestigating}
                      className="px-2.5 py-1 text-[10px] bg-slate-800 hover:bg-slate-700 font-bold border border-slate-700/80 rounded transition-all text-slate-300"
                    >
                      {isInvestigating ? "Synthesizing..." : "Analyze Session Now"}
                    </button>
                  )}
                </div>

                {/* Gemini AI synthesis state response displays */}
                {isInvestigating && (
                  <div className="p-4 bg-slate-900 border border-slate-800 rounded text-center space-y-3 animate-pulse">
                    <RefreshCw className="w-5 h-5 text-blue-500 animate-spin mx-auto" />
                    <p className="text-[11px] text-slate-300">
                      Parsing activity timestamps, cross-referencing exfiltration channels, and synthesizing forensic incident reports...
                    </p>
                  </div>
                )}

                {reportError && (
                  <div className="p-3 bg-red-950/30 border border-red-900/60 text-red-200 text-[11px] rounded leading-relaxed">
                    <strong className="text-red-400 block mb-1">Synthesis Failure:</strong>
                    {reportError}
                    <div className="mt-2 text-[10px] text-slate-400">
                      Please proceed manually with the local heuristics dashboard, or verify that your developer system has an active Gemini key. You can find this in the Settings &gt; Secrets workspace panel.
                    </div>
                  </div>
                )}

                {aiReport && !isInvestigating && (
                  <div className="space-y-4 text-xs animate-fadeIn">
                    
                    {/* RISK BADGE */}
                    <div className="flex items-center justify-between p-2 bg-slate-900 border border-slate-800/60 rounded">
                      <span className="text-[10px] font-bold text-slate-500 font-mono">RISK GRADING CATEGORY</span>
                      <span className={`px-2.5 py-0.5 text-[10px] font-black font-mono rounded border ${
                        aiReport.riskRating === "CRITICAL" ? "bg-rose-950/70 text-rose-400 border-rose-800" :
                        aiReport.riskRating === "HIGH" ? "bg-rose-950/40 text-rose-400 border-rose-900/30" :
                        aiReport.riskRating === "MEDIUM" ? "bg-amber-950/40 text-amber-400 border-amber-900/30" :
                        "bg-emerald-950/30 text-emerald-400 border-emerald-900/30"
                      }`}>
                        {aiReport.riskRating}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <h5 className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">
                        Clinical Investigative Hypothesis
                      </h5>
                      <p className="text-[11px] text-slate-300 leading-relaxed font-sans bg-slate-900 p-3 rounded border border-slate-800/40">
                        {aiReport.hypothesis}
                      </p>
                    </div>

                    <div className="space-y-2">
                      <h5 className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">
                        Intent Synthesis & Motives
                      </h5>
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        {aiReport.intentSynthesis}
                      </p>
                    </div>

                    {/* Timeline Highlights */}
                    {aiReport.timelineHighlights && aiReport.timelineHighlights.length > 0 && (
                      <div className="space-y-2">
                        <h5 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                          Reconstructed Highlights ({aiReport.timelineHighlights.length})
                        </h5>
                        <div className="space-y-2 font-mono">
                          {aiReport.timelineHighlights.map((hl, idx) => (
                            <div key={idx} className="p-2 bg-slate-900/40 rounded border border-slate-800 text-[10px] leading-relaxed">
                              <div className="text-yellow-400 font-bold mb-0.5">[{hl.timestamp}] - {hl.events}</div>
                              <div className="text-slate-400 italic">Significance: {hl.forensicSignificance}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommended SecOps Response Steps */}
                    {aiReport.mitigationSteps && aiReport.mitigationSteps.length > 0 && (
                      <div className="space-y-1.5 border-t border-slate-800/40 pt-3">
                        <h5 className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-1">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Recommended Mitigation Protocol
                        </h5>
                        <ul className="list-disc pl-4 text-slate-300 font-sans space-y-1 leading-relaxed text-[11px]">
                          {aiReport.mitigationSteps.map((step, idx) => (
                            <li key={idx} className="text-slate-400">
                              <strong className="text-slate-300">{step}</strong>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <button
                      onClick={() => setAiReport(null)}
                      className="w-full py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 font-bold text-slate-400 text-[10px] text-center"
                    >
                      Reset Investigative Synthesis Report
                    </button>
                  </div>
                )}
              </div>

              {/* ACTIVE CONSOLE CHAT QA */}
              <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/20 space-y-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-500" />
                  <h4 className="text-xs font-bold text-white">Cognitive Auditor Terminal</h4>
                </div>
                <p className="text-[10px] text-slate-500 leading-relaxed">
                  Interactively query intelligence engines directly concerning active sessions, suspicious keywords or timeline gaps.
                </p>

                {/* Chat items log */}
                {qaHistory.length > 0 && (
                  <div className="space-y-3 max-h-[220px] overflow-y-auto pr-1 border-t border-b border-slate-800/60 py-3 font-mono text-[10px]">
                    {qaHistory.map((qa, idx) => (
                      <div key={idx} className="space-y-1 bg-slate-950/50 p-2 rounded">
                        <div className="text-blue-400 font-bold flex items-center gap-1 select-none">
                          <span>$ investigator &gt;</span>
                          <span className="text-slate-300 font-semibold">{qa.q}</span>
                        </div>
                        <div className="text-slate-400 pl-3 leading-relaxed border-l border-emerald-800/45">
                          {qa.a}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Ask form */}
                <form onSubmit={handleAskQuestion} className="flex gap-2">
                  <input
                    type="text"
                    value={customQuestion}
                    onChange={(e) => setCustomQuestion(e.target.value)}
                    placeholder="Ask AI: e.g. Why did they visit bleachbit?"
                    className="flex-1 bg-slate-950 text-slate-200 placeholder-slate-650 text-xs px-3 py-2 rounded border border-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                  />
                  <button
                    type="submit"
                    disabled={isAsking || !customQuestion.trim()}
                    className="p-2 rounded bg-blue-600 hover:bg-blue-500 text-white disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed cursor-pointer transition-colors"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>

              {/* SINGLE RECORD DETAILS EXPANSION - METADATA */}
              {selectedRecord && (
                <div className="border border-slate-800/80 rounded-lg p-4 bg-slate-950/40 space-y-3">
                  <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest font-mono">
                    Node Artifact Metadata Trace
                  </h4>

                  <div className="space-y-1.5 text-[11px] font-mono">
                    <div className="flex justify-between py-1 border-b border-slate-800/50">
                      <span className="text-slate-500">Resource</span>
                      <span className="text-slate-300 font-semibold truncate max-w-[150px]">{selectedRecord.domain}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/50">
                      <span className="text-slate-500">Visit Timestamp</span>
                      <span className="text-slate-300 text-[10px]">{new Date(selectedRecord.visitTime).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/50">
                      <span className="text-slate-500">Trace Category</span>
                      <span className="text-slate-300">{selectedRecord.category}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/50">
                      <span className="text-slate-500">Anomalous Score</span>
                      <span className={`font-bold ${
                        selectedRecord.threatScore >= 70 ? "text-rose-400" :
                        selectedRecord.threatScore >= 35 ? "text-amber-400" : "text-emerald-400"
                      }`}>{selectedRecord.threatScore}%</span>
                    </div>
                  </div>

                  <div className="pt-2">
                    <a
                      href={selectedRecord.url}
                      target="_blank"
                      rel="noreferrer"
                      className="w-full py-1.5 border border-slate-700/80 font-mono text-[10px] uppercase font-bold text-slate-300 hover:bg-slate-800/50 hover:text-white transition-all rounded block text-center"
                    >
                      Visit Evidential Target URL
                    </a>
                  </div>
                </div>
              )}

            </div>
          </div>

        </section>

      </main>

    </div>
  );
}

// Inline fallback icon replacement since Users wasn't standard in lucide-react standard bundle check
function UsersIcon(props: any) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}
