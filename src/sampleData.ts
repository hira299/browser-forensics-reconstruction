/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { BrowserHistoryItem } from "./types";

// Construct a reference timestamp relative to current local time (to keep it fresh and realistic!)
const getRelativeISO = (hoursAgo: number, minutesAgo: number = 0) => {
  const date = new Date();
  date.setHours(date.getHours() - hoursAgo);
  date.setMinutes(date.getMinutes() - minutesAgo);
  return date.toISOString();
};

export const INSIDER_THREAT_CASE: BrowserHistoryItem[] = [
  {
    id: "it-1",
    url: "https://www.linkedin.com/jobs/search/?q=senior+systems+architect",
    title: "Job Search: Senior Systems Architect Opportunities | LinkedIn",
    visitTime: getRelativeISO(16, 45),
    visitCount: 2,
    typedCount: 1,
  },
  {
    id: "it-2",
    url: "https://www.google.com/search?q=how+much+intellectual+property+does+competitor+own",
    title: "how much intellectual property does competitor own - Google Search",
    visitTime: getRelativeISO(16, 12),
    visitCount: 1,
    typedCount: 1,
    searchQuery: "how much intellectual property does competitor own",
  },
  {
    id: "it-3",
    url: "https://www.google.com/search?q=how+to+bypass+network+data+loss+prevention",
    title: "how to bypass network data loss prevention - Google Search",
    visitTime: getRelativeISO(12, 30),
    visitCount: 1,
    typedCount: 1,
    searchQuery: "how to bypass network data loss prevention",
  },
  {
    id: "it-4",
    url: "https://www.reddit.com/r/cybersecurity/comments/bypass_dlp_transfer_limits",
    title: "Bypassing DLP upload restrictions on enterprise routers : cybersecurity",
    visitTime: getRelativeISO(12, 28),
    visitCount: 3,
  },
  {
    id: "it-5",
    url: "https://www.google.com/search?q=secure+temporary+file+sharing+portals",
    title: "secure temporary file sharing portals - Google Search",
    visitTime: getRelativeISO(12, 10),
    visitCount: 1,
    searchQuery: "secure temporary file sharing portals",
  },
  {
    id: "it-6",
    url: "https://gofile.io/welcome-upload-agent",
    title: "GoFile - Anonymous Online File Sharing System & Web Upload",
    visitTime: getRelativeISO(11, 58),
    visitCount: 1,
    typedCount: 1,
  },
  {
    id: "it-7",
    url: "https://www.google.com/search?q=scp+compressed+archive+split+part+rar",
    title: "scp compressed archive split part rar - Google Search",
    visitTime: getRelativeISO(11, 40),
    visitCount: 2,
    searchQuery: "scp compressed archive split part rar",
  },
  {
    id: "it-8",
    url: "https://mega.nz/file/transfer/dfa98w3bns",
    title: "MEGA File Manager - Secure Folder Exfiltration Target",
    visitTime: getRelativeISO(11, 15),
    visitCount: 4,
  },
  {
    id: "it-9",
    url: "https://www.google.com/search?q=is+mega.nz+monitored+by+mcafee+edr",
    title: "is mega.nz monitored by mcafee edr - Google Search",
    visitTime: getRelativeISO(11, 0),
    visitCount: 1,
    searchQuery: "is mega.nz monitored by mcafee edr",
  },
  {
    id: "it-10",
    url: "https://www.google.com/search?q=how+to+permanently+delete+google+chrome+browsing+history+log",
    title: "how to permanently delete google chrome browsing history log - Google Search",
    visitTime: getRelativeISO(3, 15), // Late night
    visitCount: 1,
    searchQuery: "how to permanently delete google chrome browsing history log",
  },
  {
    id: "it-11",
    url: "https://github.com/bleachbit/bleachbit/releases",
    title: "Releases · bleachbit/bleachbit · GitHub - Clean and Secure Evasion",
    visitTime: getRelativeISO(3, 10),
    visitCount: 1,
  },
  {
    id: "it-12",
    url: "https://www.google.com/search?q=clear+windows+event+viewer+log+via+powershell",
    title: "clear windows event viewer log via powershell - Google Search",
    visitTime: getRelativeISO(3, 5),
    visitCount: 1,
    searchQuery: "clear windows event viewer log via powershell",
  },
];

export const PHISHING_BREACH_CASE: BrowserHistoryItem[] = [
  {
    id: "pb-1",
    url: "https://mail.yahoo.com/d/folders/1/messages/urgent_security_alert_bank_update",
    title: "Urgent: Important Account Updates Required - Yahoo! Mail Security Workspace",
    visitTime: getRelativeISO(8, 15),
    visitCount: 2,
  },
  {
    id: "pb-2",
    url: "https://wells-fargo-support-mfa-alert.security-auth-check.net/login/auth",
    title: "Wells Fargo Secure System Verification - Security Portal Portal Link",
    visitTime: getRelativeISO(8, 12),
    visitCount: 1,
    typedCount: 1,
  },
  {
    id: "pb-3",
    url: "https://www.google.com/search?q=suspicious+withdrawals+after+wells+fargo+mfa+bypass",
    title: "suspicious withdrawals after wells fargo mfa bypass - Google Search",
    visitTime: getRelativeISO(7, 45),
    visitCount: 1,
    searchQuery: "suspicious withdrawals after wells fargo mfa bypass",
  },
  {
    id: "pb-4",
    url: "https://www.google.com/search?q=how+to+verify+caller+is+actually+from+fraud+department",
    title: "how to verify caller is actually from fraud department - Google Search",
    visitTime: getRelativeISO(7, 30),
    visitCount: 1,
    searchQuery: "how to verify caller is actually from fraud department",
  },
  {
    id: "pb-5",
    url: "https://www.coinbase.com/dashboard",
    title: "Coinbase - Digital Wallet Access Portfolio Tracker",
    visitTime: getRelativeISO(6, 12),
    visitCount: 3,
  },
  {
    id: "pb-6",
    url: "https://metamask-security-alert-verify.io/index.html",
    title: "Metamask Extension Recovery System - Unlock Recovery Phrase",
    visitTime: getRelativeISO(6, 5),
    visitCount: 1,
    typedCount: 1,
  },
  {
    id: "pb-7",
    url: "https://www.google.com/search?q=what+to+do+if+metamask+private+key+is+shared",
    title: "what to do if metamask private key is shared - Google Search",
    visitTime: getRelativeISO(5, 50),
    visitCount: 1,
    searchQuery: "what to do if metamask private key is shared",
  },
  {
    id: "pb-8",
    url: "https://free-cracked-software-download.blogspot.com/2026/05/get-pro-forensics-toolkit",
    title: "Free Forensic Toolkits & Keygenerators - Download Site",
    visitTime: getRelativeISO(2, 40), // Late night
    visitCount: 2,
  },
  {
    id: "pb-9",
    url: "https://www.google.com/search?q=how+to+disable+windows+defender+via+registry+keys",
    title: "how to disable windows defender via registry keys - Google Search",
    visitTime: getRelativeISO(2, 35),
    visitCount: 1,
    searchQuery: "how to disable windows defender via registry keys",
  },
];

export const STANDARD_BASELINE_CASE: BrowserHistoryItem[] = [
  {
    id: "sb-1",
    url: "https://news.ycombinator.com/",
    title: "Hacker News",
    visitTime: getRelativeISO(10, 0),
    visitCount: 4,
    typedCount: 2,
  },
  {
    id: "sb-2",
    url: "https://github.com/trending",
    title: "Trending repositories on GitHub today",
    visitTime: getRelativeISO(9, 45),
    visitCount: 1,
  },
  {
    id: "sb-3",
    url: "https://www.google.com/search?q=tailwind+css+v4+import+theme+directive",
    title: "tailwind css v4 import theme directive - Google Search",
    visitTime: getRelativeISO(8, 20),
    visitCount: 1,
    searchQuery: "tailwind css v4 import theme directive",
  },
  {
    id: "sb-4",
    url: "https://tailwindcss.com/docs/api-theme",
    title: "Theme Configuration & Utility Classes - Tailwind CSS Docs",
    visitTime: getRelativeISO(8, 18),
    visitCount: 2,
  },
  {
    id: "sb-5",
    url: "https://stackoverflow.com/questions/7788192/react-functional-component-mount-twice",
    title: "javascript - Why does my React functional component mount twice in dev? - Stack Overflow",
    visitTime: getRelativeISO(7, 10),
    visitCount: 3,
  },
  {
    id: "sb-6",
    url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    title: "Rick Astley - Never Gonna Give You Up (Official Music Video) - YouTube",
    visitTime: getRelativeISO(6, 30),
    visitCount: 1,
  },
  {
    id: "sb-7",
    url: "https://github.com/reactjs/react-router/issues/9924",
    title: "React Router v7 loaders firing multiple times · Issue #9924 · facebook/react",
    visitTime: getRelativeISO(3, 40),
    visitCount: 2,
  },
  {
    id: "sb-8",
    url: "https://chat.openai.com/chat/general-coding-help",
    title: "ChatGPT - React Bug Troubleshooting Module",
    visitTime: getRelativeISO(2, 50),
    visitCount: 5,
  },
];
