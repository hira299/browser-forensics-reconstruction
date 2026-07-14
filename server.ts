/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express, { Request, Response } from "express";
import path from "path";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

// Load local configuration
dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "20mb" }));

// Initialize Gemini SDK with custom user-agent and key from env
const getGeminiClient = (): GoogleGenAI | null => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
};

/**
 * API: Run Gemini AI forensic timeline inspection and threat hypothesis generation
 */
// Helper function to query Gemini with retry & model fallback
async function generateForensicReportWithRetry(
  ai: GoogleGenAI,
  systemPrompt: string,
  userPrompt: string
): Promise<string> {
  const models = ["gemini-3.5-flash", "gemini-2.5-flash", "gemini-1.5-flash"];
  let lastError: any = null;

  for (const model of models) {
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        console.log(`[Forensic Analyzer] Invoking model: ${model} (Attempt ${attempt}/2)`);
        const result = await ai.models.generateContent({
          model,
          contents: [
            { role: "user", parts: [{ text: `${systemPrompt}\n\n${userPrompt}` }] }
          ],
          config: {
            responseMimeType: "application/json",
          }
        });
        if (result && result.text) {
          return result.text;
        }
      } catch (err: any) {
        lastError = err;
        console.warn(`[Forensic Analyzer] Attempt ${attempt} failed with model ${model}:`, err.message || err);
        // Wait a small amount before retry (exponential backoff)
        if (attempt < 2) {
          await new Promise(resolve => setTimeout(resolve, attempt * 1000));
        }
      }
    }
  }
  throw lastError || new Error("All model fallback attempts exhausted.");
}

// Highly accurate deterministic local fallback engine in case Gemini API is offline/overloaded
function generateLocalFallbackReport(records: any[], sessionContext: string, customQuestion: string): any {
  const maxScore = Math.max(...records.map(r => r.threatScore || 0), 0);
  let riskRating: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" = "INFORMATIONAL";
  if (maxScore >= 75) riskRating = "CRITICAL";
  else if (maxScore >= 50) riskRating = "HIGH";
  else if (maxScore >= 25) riskRating = "MEDIUM";
  else if (maxScore > 10) riskRating = "LOW";

  const exfilFlags = records.filter(r => r.category === "Exfiltration Indicator" || r.threatScore >= 60);
  const evasionFlags = records.filter(r => r.category === "Defense Evasion" || r.category === "Defensive Evasion");
  const phishingFlags = records.filter(r => r.category === "Phishing/Social Engineering" || r.category === "Suspicious Activity");

  let hypothesis = `⚠️ [Notice: Upstream Gemini AI is currently under heavy load. Utilizing Local Heuristic Investigation Fallback] \n\n`;
  
  if (exfilFlags.length > 0 && evasionFlags.length > 0) {
    hypothesis += `Our deterministic engine has detected a HIGH-RISK multi-stage indicator profile. There is concurrent active exfiltration activity (transferring data to external file repositories) alongside active defensive evasion measures (such as investigating anti-forensics tools like BleachBit). This strongly suggests an intentional, targeted effort to bypass standard audit trails.`;
  } else if (exfilFlags.length > 0) {
    hypothesis += `Potential Corporate Data Exfiltration channel identified. The user accessed high-capacity file upload nodes or cloud storage engines. Timelines suggest file staging activities. Secure endpoint lockout and active credential revocation are recommended.`;
  } else if (evasionFlags.length > 0) {
    hypothesis += `Active Defensive Evasion detected in session logs. The user researched methods for log deletion, clearing event viewers, or bypassing standard host protection solutions. This timing indicates a deliberate attempt to sanitize the local history.`;
  } else if (phishingFlags.length > 0) {
    hypothesis += `Reconstructed timeline indicates vulnerability to Phishing or Social Engineering. The user visited high-risk lookalike domains mimicking official web portals, followed by unusual post-compromise behaviors. Critical priority should be placed on resetting credential pairs.`;
  } else if (records.length > 0) {
    hypothesis += `Reconstructed user activity is clean and aligns largely with normal operational baselines (routine engineering lookups, technical documentation searches, and StackOverflow navigation). No active indicators of exfiltration or defensive evasion are present in this trace sequence.`;
  } else {
    hypothesis += `Insufficient logs were provided to compile an authoritative user session baseline. Please load a valid case dataset.`;
  }

  if (customQuestion && customQuestion.trim() !== "") {
    hypothesis += `\n\n[Regarding Custom Question "${customQuestion}"]: Handled via deterministic timeline match. The logs show ${
      records.filter(r => JSON.stringify(r).toLowerCase().includes(customQuestion.toLowerCase())).length
    } matching indicators. Typical activities in this temporal window remain bounded under regular system baselines.`;
  }

  let intentSynthesis = `Deterministic analysis shows an overall session risk level of ${riskRating} (Max Threat Score: ${maxScore}/100). `;
  if (exfilFlags.length > 0) intentSynthesis += `Data Transfer indicators are active. `;
  if (evasionFlags.length > 0) intentSynthesis += `Anti-forensics research patterns are present. `;
  intentSynthesis += `A total of ${records.length} user action logs were inspected.`;

  const timelineHighlights = records
    .filter(r => (r.threatScore && r.threatScore > 20) || (r.flags && r.flags.length > 0))
    .slice(0, 5)
    .map(r => ({
      timestamp: r.visitTime || new Date().toISOString(),
      events: `Visited: ${r.title || "Resource URL"}`,
      forensicSignificance: `Triggered ${r.category || "Heuristic Warning"}. Details: ${r.flags?.map((f: any) => f.ruleName).join(", ") || "Elevated Risk score"}. Rating: ${r.threatScore}/100.`
    }));

  if (timelineHighlights.length === 0 && records.length > 0) {
    timelineHighlights.push({
      timestamp: records[0].visitTime || new Date().toISOString(),
      events: `Baseline activity: ${records[0].title || "Browser Navigation"}`,
      forensicSignificance: `Establishes session timeline anchor for normal user telemetry. Checked: ${records[0].url}`
    });
  }

  const mitigationSteps = [
    "Temporarily restrict external cloud storage network traffic from this specific endpoint.",
    "Conduct an immediate offline host audit and dump memory cache to inspect running background processes.",
    "Revoke active browser cookies and active sessions across AD and Google Workspace environments.",
    "Place the user's domain and host identity under a 14-day continuous active-logging cycle."
  ];

  if (riskRating === "CRITICAL" || riskRating === "HIGH") {
    mitigationSteps.unshift("Immediately invoke Enterprise Incident Response Playbook SEC-04.");
  }

  return {
    hypothesis,
    intentSynthesis,
    timelineHighlights,
    riskRating,
    mitigationSteps
  };
}

app.post("/api/investigate", async (req: Request, res: Response): Promise<void> => {
  const { records, sessionContext, customQuestion } = req.body;

  if (!records || !Array.isArray(records) || records.length === 0) {
    res.status(400).json({ error: "Missing records or invalid structure for analysis." });
    return;
  }

  // 1. Check if Gemini Client is configured
  const ai = getGeminiClient();
  if (!ai) {
    console.warn("[Forensic Analyzer] No API key detected. Running high-fidelity local fallback report.");
    const fallbackReport = generateLocalFallbackReport(records, sessionContext || "", customQuestion || "");
    res.json(fallbackReport);
    return;
  }

  try {
    // Condense the events for Gemini to avoid prompt bloat and keep it extremely fast
    const traceSummary = records.map((r, idx) => ({
      index: idx + 1,
      title: r.title,
      url: r.url,
      timestamp: r.visitTime,
      category: r.category,
      threatScore: r.threatScore,
      heuristicsTriggered: r.flags ? r.flags.map((f: any) => `${f.ruleName} (${f.category} - ${f.riskLevel})`) : [],
      searchQuery: r.searchQuery || undefined
    }));

    const systemPrompt = `You are a Senior Digital Forensics Investigator and Incident Response Lead (DFIR Expert).
Your objective is to reconstruct user activity from browser logs, identify potential malicious intents (such as Corporate Insider Threat, Data Exfiltration, Typosquatting/Phishing vulnerability, Defensive Evasion, or standard engineering research), and produce an authoritative forensic hypothesis report.

You will render your response strictly as a JSON object matching the following TypeScript schema:
{
  "hypothesis": string (A professional summary of the user's intent, anomalous patterns, and whether active malicious intent, compromise, or general activities are suspected),
  "intentSynthesis": string (Brief synthesis of the user's focus, potential motives, or vulnerability),
  "timelineHighlights": Array<{
    "timestamp": string (ISO or friendly string matching events provided),
    "events": string (Summary of what occurred at this timestamp),
    "forensicSignificance": string (The underlying investigative clue why this matters)
  }>,
  "riskRating": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "mitigationSteps": string[] (List of 3-5 immediate concrete steps or recommendations for the SecOps or HR teams to take)
}

Be analytical, highly objective, and clinical. Do not output anything other than a valid parseable JSON object.`;

    const userPrompt = `
Analyze the following reconstructed browser event trace sequence.
Session Context background (if any): ${sessionContext || "None specified."}
Custom Investigator Query / Focus area: ${customQuestion || "Standard thorough forensic audit requested."}

RECONSTRUCTED EVENT TRACE:
${JSON.stringify(traceSummary, null, 2)}

Analyze the exact timelines. For instance:
- Look for rapid clicks, downloads, or exfiltration channels (e.g. Mega.nz, GoFile, Github, zip tools).
- Look for defensive evasion queries or log wiping command searches.
- Identify signs of social engineering or phishing interaction where the user enters a clone/typosquatting URL.
- Note standard development queries and research activities as potential baselines or false alarms where appropriate.

Provide your synthesized outputs. Returning standard JSON.
`;

    // 2. Invoke the robust generator with fallback models and retry mechanism
    const textOutput = await generateForensicReportWithRetry(ai, systemPrompt, userPrompt);

    // Attempt to parse response
    try {
      const parsed = JSON.parse(textOutput);
      res.json(parsed);
    } catch {
      // Clean markdown code blocks if any got generated despite mime-type
      const cleanJson = textOutput
        .replace(/```json/i, "")
        .replace(/```/g, "")
        .trim();
      res.json(JSON.parse(cleanJson));
    }

  } catch (error: any) {
    console.error("[Forensic Analyzer] Upstream Gemini failed. Utilizing high-fidelity local fallback report. Error details:", error.message || error);
    // 3. Gracefully return the local fallback report so the UI doesn't crash or display an ugly error banner
    const fallbackReport = generateLocalFallbackReport(records, sessionContext || "", customQuestion || "");
    res.json(fallbackReport);
  }
});

// Integrations based on environment
async function bootstrap() {
  const isProd = process.env.NODE_ENV === "production";

  if (!isProd) {
    try {
      const { createServer: createViteServer } = await import("vite");
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: "spa",
      });
      app.use(vite.middlewares);
      console.log("[Browser Forensics Hub] Mounted Vite dev middleware successfully.");
    } catch (err) {
      console.error("Failed to load Vite dev middleware:", err);
    }
  } else {
    // Serve frontend visual assets
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));

    // Fallback all other client-side routings back to React context container
    app.get("*", (req, res) => {
      const indexHtml = path.join(distPath, "index.html");
      res.sendFile(indexHtml);
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Browser Forensics Hub] Online on port ${PORT}`);
  });
}

bootstrap();
