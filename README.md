# Browser Forensics and User Activity Reconstruction Console

[![Forensics](https://img.shields.io/badge/DFIR-Digital%20Forensics-blue.svg)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](#)
[![React](https://img.shields.io/badge/React-19-blue.svg)](#)
[![Gemini AI](https://img.shields.io/badge/Cognitive%20Synthesis-Gemini%203.5-purple.svg)](#)

An advanced, research-oriented digital forensics and incident response (DFIR) platform designed to parse, reconstruct, and dynamically audit browser historical logs. Built with high-fidelity heuristic detection models and powered by Gemini-3.5-Flash server-side cognitive synthesis, this console bridges raw web artifacts with actionable threat intelligence and structured incident hypotheses.

This repository implements the practical core and architectural prototype of browser history forensics. It aligns closely with modern academic paradigms in **user behavior modeling**, **insider threat mitigation**, and **automated forensic timelines construction**.

---

## 🔬 Project Overview

In digital forensics, browser history represents a critical window into user intent, malicious timelines, and potential insider threats. However, raw database dumps (SQLite, JSON, CSV) often suffer from structural clutter, noise, and semantic dilution. 

**Browser Forensics and User Activity Reconstruction Console** addresses this challenge by converting raw timestamped browsing sequences into structured **Activity Sessions** and running them through a dual-layered inspection framework:
1. **Deterministic Heuristic Layer**: Evaluates domains, query terms, sub-paths, and timing anomalies against signature patterns for exfiltration, defensive evasion, shadow IT, and typosquatting/phishing.
2. **Cognitive Synthesis Layer**: Leverages Gemini API models (`gemini-3.5-flash`) to generate clinical forensic hypotheses, construct event sequences, and formulate actionable SecOps mitigation playbooks.

---

## 🚀 Key Features

### 1. Chronological Activity Reconstruction (Temporal Sessioning)
* **Gap-Threshold Clustering**: Groups individual logs into cohesive sessions based on configurable idle periods (defaulting to a 40-minute threshold). This accurately models continuous user focus states rather than isolated web hits.
* **Semantic Labeling**: Dynamically extracts prevailing session activity categories (e.g., *Suspicious Data Exfiltration Routing*, *Forensic Defenses & Clear Operation*, *Targeted Competitor Intelligence Gathering*).

### 2. High-Fidelity Heuristic Threat Engine
The detection engine systematically evaluates raw events and logs to identify signature threat profiles:
* **Unauthorized Exfiltration Channels**: Tracks connection endpoints with high-capacity transfer clouds (e.g., `Mega.nz`, `GoFile.io`).
* **Defensive Evasion Patterns**: Flags searches or software downloads associated with audit trail destruction (e.g., `BleachBit`, log wiper scripts, disabling host EDR software).
* **Typosquatting & Phishing Identification**: Isolates visits to suspicious lookalike domains mimicking official banking or cryptocurrency nodes.
* **Off-Hours Temporal Anomaly**: Highlights off-hours operations (00:00 - 05:00) paired with sensitive research.

### 3. Server-Side AI Deep Scan (Cognitive Investigator)
* **Automated Forensic Reports**: Instantly generates an analytical, clinical summary including suspected intent, threat classification, and chronological highlights with forensic significance.
* **Interactive Chat & Query Console**: Allows investigators to query the dataset using natural language (e.g., *"Did the suspect perform any actions indicating data compression or evasion between 2 AM and 3 AM?"*).

### 4. Interactive DFIR Playbook & Multi-Format Ingestion
* Includes a built-in forensic playbook outlining corporate standards for exfiltration tracking, evasion detection, and baselining.
* Supports manual file uploads (Chrome JSON exports, standard schema CSVs) with drag-and-drop and fallback auto-parsers.

---

## 🛠️ Technological Architecture

The application is engineered as a highly optimized full-stack TypeScript environment:

```
                  ┌──────────────────────────────────────────────┐
                  │            Vite React SPA Frontend           │
                  │   - Interactive Timeline Visualization     │
                  │   - Session Detail & Threat Metrics        │
                  │   - Interactive Investigator Chat Console  │
                  └──────────────────────┬───────────────────────┘
                                         │ JSON Requests
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │            Express NodeJS Backend            │
                  │   - Dynamic Static Asset Routing             │
                  │   - Safe API Proxying                        │
                  └──────────────────────┬───────────────────────┘
                                         │ Secure Payload Proxies
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │              Gemini AI Integration           │
                  │   - Server-Side Gemini 3.5 Flash Model       │
                  │   - Schema-Enforced JSON Output              │
                  └──────────────────────────────────────────────┘
```

* **Frontend**: React 19, Vite, Tailwind CSS (Modern Slate Aesthetic), Lucide Icons, and Motion animations.
* **Backend**: Express, Node.js, `tsx` server runtime environment.
* **Forensics Engine**: Core algorithms in pure TypeScript, delivering deterministic threat scoring (0-100), domain extracting rules, and multi-format CSV/JSON parsers.

---

## ⚙️ Local Installation & Setup

Follow these steps to establish a local instance of the console on your machine:

### Prerequisites
* **Node.js**: Version 18.x or higher
* **npm**: Version 9.x or higher
* **Gemini API Key**: Obtainable via [Google AI Studio](https://aistudio.google.com/)

### 1. Clone the Repository
```bash
git clone https://github.com/hira299/browser-forensics.git
cd browser-forensics
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory (you can copy `.env.example` as a starting point):
```bash
cp .env.example .env
```
Populate your configuration values inside `.env`:
```env
GEMINI_API_KEY="your_actual_gemini_api_key_here"
PORT=3000
```

### 4. Run the Dev Server
Launch the development environment:
```bash
npm run dev
```
The application will boot and serve locally at `http://localhost:3000`.

### 5. Production Build & Execution
To compile the production assets and start the production server:
```bash
npm run build
npm start
```

---

## 📊 Sample Datasets & Sandboxed Scenarios

The platform includes pre-configured high-fidelity sandbox scenarios to demonstrate and validate features immediately:
* **Suspect Case: Insider Threat**: Models a systems architect searching career options, researching DLP bypass tricks, accessing unapproved cloud repositories, and investigating log-wiping programs in the middle of the night.
* **Suspect Case: Phishing Hack**: Models an employee receiving urgent security mail, entering sensitive lookalike domains, encountering financial crypto wallet recovery traps, and trying to disable standard defender suites.
* **Baseline Normalization**: Demonstrates standard technical activities (Hacker News browsing, Tailwind CSS documentation lookups, StackOverflow queries) showing a clean baseline.

---

## 📑 Core Forensic Code Structure

* **`/server.ts`**: Express backend server handling Vite dev middlewares and safe API proxies to Gemini API, ensuring zero client-side API key leakage.
* **`/src/forensicsEngine.ts`**: The algorithmic engine. Contains parsing algorithms, temporal session clustering logic, and forensic heuristics threat rule configurations.
* **`/src/types.ts`**: Static typing declarations for browsed history items, flagged warnings, user sessions, and AI investigation schemas.
* **`/src/App.tsx`**: Rich, responsive unified workspace dashboard integrating forensic charts, timeline widgets, and the investigator chat panel.

---

## 🎓 Academic Alignment & Research Value

This implementation correlates directly with methodologies detailed in publications addressing automated digital investigations, behavioral pattern mapping, and cyber security intelligence. 

By automating the reconstruction of raw logs into structured visual timelines and leveraging state-of-the-art cognitive language systems to build hypotheses, the platform reduces cognitive load for SOC analysts, incident response teams, and HR forensics departments during high-pressure audits.

---

## ⚖️ License & Contributions

* Licensed under the Apache-2.0 License.
* Developed for academic research, digital forensic analysis, and secure code validation.

*For inquiries, academic collaborations, or issues regarding this implementation, feel free to open a pull request or contact **hira299**.*
