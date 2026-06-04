# Product Requirements Document
## Project Compass — AI Governance & Risk Management Platform
**Version:** 1.0  
**Date:** June 2026  
**Status:** Draft  
**Author:** MICS Capstone Team

---

## Table of Contents
1. [Overview](#1-overview)
2. [Problem Statement](#2-problem-statement)
3. [Target Users](#3-target-users)
4. [Product Goals](#4-product-goals)
5. [MVP Scope & Boundaries](#5-mvp-scope--boundaries)
6. [Application Architecture](#6-application-architecture)
7. [Feature Requirements — Step by Step](#7-feature-requirements--step-by-step)
8. [After-Scan Actions](#8-after-scan-actions)
9. [Risk Scoring Logic](#9-risk-scoring-logic)
10. [Gap Assessment Questions](#10-gap-assessment-questions)
11. [Report Specifications](#11-report-specifications)
12. [AI Tool Domain Registry](#12-ai-tool-domain-registry)
13. [Sample Data Requirements](#13-sample-data-requirements)
14. [Backend & Technical Requirements](#14-backend--technical-requirements)
15. [State & Data Management](#15-state--data-management)
16. [Non-Functional Requirements](#16-non-functional-requirements)
17. [Out of Scope for MVP](#17-out-of-scope-for-mvp)
18. [Success Criteria](#18-success-criteria)
19. [Open Questions](#19-open-questions)
20. [Build Priority & Phasing](#20-build-priority--phasing)

---

## 1. Overview

Compass is a web application that helps organizations discover AI tools in use across their environment, assess governance gaps against the NIST AI Risk Management Framework (AI RMF), and generate actionable reports for security, compliance, and leadership audiences.

The product is evidence-first: every finding originates from technical log data, not employee self-reporting. The MVP is designed for a capstone demo environment using pre-built sample log files and a simulated detection flow.

---

## 2. Problem Statement

Organizations are adopting AI tools faster than governance frameworks can keep pace. The result is unmanaged risk:

- Employees use AI tools (ChatGPT, Copilot, Grammarly, etc.) on corporate networks without IT approval
- Sensitive company data, customer PII, and intellectual property is being sent to external AI services
- No policies, ownership, or monitoring exists for these tools in most mid-size organizations
- Security and compliance teams have no visibility into what AI tools are in use or how they are being used
- When asked, employees often underreport or are unaware of what qualifies as an "AI tool"
- Audit teams cannot produce structured findings without evidence — memory-based inventories are insufficient

**Core insight:** The evidence already exists in network logs. DNS queries, firewall logs, and proxy traffic contain the full picture of AI tool usage. Compass reads this evidence and turns it into governance intelligence.

---

## 3. Target Users

### Primary User — Security Lead
The security lead is the MVP user. They run the full Compass workflow from upload to dashboard.

**Goals:**
- Discover what AI tools are being used on the network without asking employees
- Understand which tools pose the highest data risk
- Get a prioritized action list (what to block first, what to monitor)
- Produce evidence-backed reports they can hand to leadership and audit

**Pain points:**
- No existing tool surfaces AI-specific network risk
- Existing DLP and CASB tools flag data movement but not AI governance gaps
- Leadership asks for an AI inventory but no reliable method exists

---

### Secondary Users

| User | Primary Need | Report View |
|---|---|---|
| Compliance Officer | Map AI usage to policy requirements. Find gaps before audit. | Auditor |
| Auditor | Structured findings with evidence, dates, and framework mapping | Auditor |
| Business Leader / CISO | Business impact and top decisions. No technical detail. | Executive |

---

## 4. Product Goals

### Demo Goals (Capstone)
1. Walk a live audience through the full 6-step workflow in under 10 minutes
2. Show a realistic detection of AI tools from a sample log file
3. Produce a dashboard that clearly shows risk and next actions
4. Generate at least one audience-specific report that could be handed to leadership

### Product Goals (Post-Capstone Direction)
1. Support real log file uploads from enterprise environments
2. Integrate with SIEM tools (Splunk, Microsoft Sentinel) for continuous monitoring
3. Support Active Directory and cloud provider API integrations for automated blocking
4. Expand the AI tool domain registry to 500+ services with automatic updates

---

## 5. MVP Scope & Boundaries

### In Scope
- Landing page (complete)
- 6-step application workflow (Steps 1–6)
- Simulated log detection using pre-built sample files
- AI tool inventory with review state management
- Gap assessment questionnaire (NIST AI RMF mapped)
- Risk dashboard with scores and top actions
- Two after-scan action flows: Block and Monitor
- Three report audience views: Executive, Security, Auditor
- PDF export (browser print or jsPDF)

### Demo Approach — Simulated vs. Real
For the capstone demo, log parsing is **simulated**:
- The app accepts any file upload (accepts .log, .txt, .csv, .json)
- If the file matches a known sample filename OR within 30 seconds, the app loads predetermined detection results
- This gives the appearance of real analysis while guaranteeing a controlled, demo-ready outcome
- The detection results, inventory, and dashboard data are all seeded from a static JSON dataset

This approach is explicitly acceptable under the project guidelines: "The demo should use sample or scrubbed logs."

---

## 6. Application Architecture

### Page Structure

```
/ ..................... Landing page (complete)
/app ................. App shell — persistent nav + step progress bar
/app/upload .......... Step 1: Upload Logs
/app/detect .......... Step 2: Detection Results
/app/inventory ....... Step 3: AI Inventory
/app/assess .......... Step 4: Gap Assessment
/app/dashboard ....... Step 5: Dashboard + Actions
/app/report .......... Step 6: Export Reports
```

### Navigation Model
- Persistent left sidebar or top progress bar showing all 6 steps
- Steps are linear — user cannot skip ahead without completing current step
- Exception: dashboard and report steps can be revisited freely after first completion
- Each step shows: step number, step name, status (Pending / In Progress / Complete)

### Visual Design
- Matches the landing page style: deep navy background, starfield, Montserrat + Inter fonts
- Brand colors: Navy `#030b1e`, Blue `#4082E8`, Teal `#33CDB6`, Orange `#FF8020`
- Cards, tables, and modals follow the glass-card pattern from the landing page
- All screens must feel like one cohesive product

---

## 7. Feature Requirements — Step by Step

---

### Step 1 — Upload Logs

**Purpose:** Accept log file(s) from the user and begin the analysis flow.

**UI Requirements:**
- Large drag-and-drop upload zone, centered, with dashed border
- "Or click to browse" fallback
- Accepted formats clearly stated: `.log`, `.txt`, `.csv`, `.json`
- After file selected: show file card with filename, size, type icon, and remove button
- Support multiple file upload (up to 3 files for demo)
- "Begin Analysis" primary button — disabled until at least one file is selected
- Small note: "Your log data is processed locally and not stored after this session"

**Log Type Labels (user selects per file):**
- DNS Log
- Firewall Log
- Web Proxy Log
- Cloud Activity Log (AWS/Azure/GCP)

**Flow after "Begin Analysis":**
1. Button shows spinner, label changes to "Analyzing..."
2. Animated progress bar runs (simulated, 2–4 seconds)
3. Progress messages cycle: "Reading log entries..." → "Matching AI domains..." → "Scoring risk..."
4. Auto-navigate to Step 2 on completion

**Acceptance Criteria:**
- [ ] User can drag-and-drop a file
- [ ] User can click to browse and select a file
- [ ] File card shows correct metadata after selection
- [ ] Begin Analysis button is disabled with no file selected
- [ ] Animated analysis sequence runs for 2–4 seconds
- [ ] User is navigated to Step 2 after analysis completes

---

### Step 2 — Detection Results

**Purpose:** Show what AI tools were found in the uploaded logs, with evidence and confidence scoring.

**UI Requirements:**

**Summary bar at top:**
- Total log entries scanned (simulated number, e.g., "14,382 log entries analyzed")
- AI tools detected count
- High risk count (orange badge)
- Analysis timestamp

**Detection table columns:**
| Column | Description |
|---|---|
| Tool Name | Display name (e.g., "ChatGPT") |
| Domain | The matched domain (e.g., `api.openai.com`) |
| Risk Level | HIGH / MEDIUM / LOW badge |
| Source Log | Which uploaded file contained the hit |
| Users / IPs | User account or source IP from the log |
| Requests | Number of times this domain was hit |
| First Seen | Timestamp of first hit in the log |
| Confidence | HIGH / MEDIUM / LOW — how certain the match is |

**Expandable row:**
- Clicking a row expands to show the actual log line(s) that triggered the match
- Show 1–3 representative log entries in monospace font
- "View all N entries" link if more than 3

**Filters:**
- Risk Level (All / High / Medium / Low)
- Log source (All / by filename)
- Sort by: Risk Level, Tool Name, Request Count

**Action buttons per row:**
- "Add to Inventory" (adds to Step 3 with status Unreviewed)
- "Dismiss" (removes from detection, logs reason)

**Bottom bar:**
- "Add All to Inventory" button — bulk adds all detected tools
- "Continue to Inventory" primary button

**Acceptance Criteria:**
- [ ] Summary statistics display correctly
- [ ] Table shows all detected tools with correct metadata
- [ ] Rows expand to show sample log evidence
- [ ] Filters work correctly
- [ ] "Add to Inventory" and "Add All" function correctly
- [ ] Navigation to Step 3 works

---

### Step 3 — AI Inventory

**Purpose:** Present a clean, reviewed inventory of AI tools found in the environment. Allow the security lead to assign review states.

**UI Requirements:**

**Inventory table columns:**
| Column | Description |
|---|---|
| Tool Name | With vendor logo placeholder |
| Category | Generative AI / Code Assistant / Writing / Image / Productivity |
| Risk Level | HIGH / MEDIUM / LOW badge |
| Evidence | Log source reference |
| Users | Count of unique users/IPs observed |
| First Detected | Date from log |
| Review Status | Unreviewed / Approved / Flagged / Blocked |
| Actions | Dropdown: Approve, Flag for Review, Block, View Evidence |

**Review status definitions:**
- **Unreviewed** — detected, not yet acted on (default)
- **Approved** — security team has reviewed and approved use
- **Flagged for Review** — needs further investigation or policy decision
- **Blocked** — marked for blocking (connects to after-scan action)

**Filters and controls:**
- Filter by: Review Status, Risk Level, Category
- Search by tool name
- Bulk select with "Apply Status To Selected" action
- Export inventory as CSV

**Summary cards above table:**
- Total tools: N
- Unreviewed: N
- High Risk: N
- Blocked: N

**Side panel (on row click):**
- Full tool detail: vendor, data processing policy URL, known data retention terms
- Risk justification: why this tool is rated High/Medium/Low
- Evidence: log entries supporting the detection
- NIST reference: which function this tool's risk maps to
- Recommended action

**Acceptance Criteria:**
- [ ] All detected tools appear in inventory
- [ ] Review status can be changed per row
- [ ] Bulk status update works
- [ ] Filters and search function correctly
- [ ] Side panel opens with correct tool detail
- [ ] CSV export generates correctly
- [ ] "Continue to Assessment" button navigates to Step 4

---

### Step 4 — Gap Assessment

**Purpose:** Ask the security lead a structured set of governance questions. Map answers to NIST AI RMF functions. Generate a gap score per function.

**UI Requirements:**

**Layout:**
- Left sidebar: NIST function progress (Govern / Map / Measure / Manage), showing completion %
- Main area: current section's questions
- Progress bar at top: "Question 7 of 16"
- Back / Next navigation

**Question format:**
- Question text (plain language, no framework jargon in the question itself)
- Answer options: Yes / No / Partial / Unsure
- Optional: "Notes" text field for each question
- NIST reference shown subtly below the question (e.g., "NIST AI RMF — Govern 1.1")

**Scoring per answer:**
- Yes = 100 points
- Partial = 50 points
- No = 0 points
- Unsure = 0 points (treated as No for scoring, flagged for follow-up)

**On section completion:**
- Show section score (e.g., "Govern: 40% maturity")
- Brief plain-language summary of gaps found in this section
- "Next Section" button

**On full assessment completion:**
- Show overall maturity breakdown before navigating to dashboard
- Summary: "You answered 9 of 16 questions with Yes or Partial. 7 gaps were identified."
- Auto-generate gap findings list (used in dashboard and reports)

**Acceptance Criteria:**
- [ ] All 16 questions display correctly across 4 sections
- [ ] Scoring calculates correctly per section and overall
- [ ] Gap findings are generated from "No" and "Unsure" answers
- [ ] NIST references appear for each question
- [ ] Section completion summaries display
- [ ] Navigation to Step 5 works

---

### Step 5 — Dashboard + Actions

**Purpose:** Combine detection results and assessment gaps into a unified risk view. Surface the highest risks first and present the top two after-scan actions.

**UI Requirements:**

**Top row — summary cards:**
- Overall Risk Score: HIGH / MEDIUM / LOW with numeric score (0–100)
- AI Tools Found: N (from Step 2)
- Governance Gaps: N (from Step 4)
- Actions Required: N

**NIST Maturity Bar (4 functions):**
- Horizontal bars for Govern / Map / Measure / Manage
- Each bar: percentage + color (red <40%, yellow 40–70%, green >70%)
- Click any bar to jump to that section's gaps

**High Risk Findings list:**
- Ranked by severity (combined tool risk + governance gap)
- Each finding card shows:
  - Finding title (plain language)
  - Risk level badge
  - Source: "Detected tool" or "Assessment gap" or "Combined"
  - NIST function reference
  - One-line recommended action
  - "View Detail" link

**Top Actions section:**
- Two prominent action cards (MVP focus):
  1. **Block Risky Tools** — orange, high emphasis
  2. **Add Monitoring** — blue, secondary emphasis
- Each card: action title, brief description, count of affected tools, "Take Action" button
- "Take Action" opens the after-scan action modal (see Section 8)

**Role view toggle:**
- Tabs or toggle: Executive / Security / Auditor
- Switches the framing and language of the dashboard without changing underlying data
- Executive: hides technical detail, shows business impact language
- Security: shows full technical detail, log references, NIST codes
- Auditor: shows structured finding format with dates, evidence, and scope

**Acceptance Criteria:**
- [ ] Summary cards show correct counts from previous steps
- [ ] NIST maturity bars calculate correctly from assessment answers
- [ ] Findings list is ranked by severity
- [ ] Block action modal opens and functions (see Section 8)
- [ ] Monitor action modal opens and functions (see Section 8)
- [ ] Role view toggle changes dashboard framing
- [ ] "Continue to Reports" navigates to Step 6

---

### Step 6 — Export Reports

**Purpose:** Generate audience-specific reports from the complete assessment data.

**UI Requirements:**

**Report selector:**
- Three report cards: Executive / Security / Auditor
- Each card: audience description, what's included, estimated length
- "Preview" button: opens report in a full-screen preview pane
- "Export PDF" button: triggers browser print or jsPDF download

**Report preview pane:**
- Full report rendered in HTML (print-optimized CSS)
- Compass branding: logo, colors, report date, organization placeholder
- "Close Preview" and "Export PDF" buttons in a fixed top bar

**All three reports share:**
- Compass logo and report title
- Date of assessment
- Organization name (editable field on this screen, defaults to "Your Organization")
- Summary of what was assessed (log types, date range, tool count)
- Finding count and overall risk rating

**See Section 11 for full report content specifications.**

**Acceptance Criteria:**
- [ ] All three report types can be previewed
- [ ] Report content matches the role-specific specifications
- [ ] PDF export functions (at minimum via browser print dialog)
- [ ] Organization name is editable
- [ ] Reports include Compass branding

---

## 8. After-Scan Actions

### Action 1 — Block Risky Tools

**Trigger:** User clicks "Take Action" on the Block card in the dashboard.

**Modal content:**
- Title: "Block Risky AI Tools"
- List of tools recommended for blocking (all tools rated HIGH risk with status Unreviewed or Flagged)
- Each tool: name, domain(s), reason for block recommendation
- Dropdown: "Select blocking method" — DNS Block / Firewall Rule / Proxy Policy (demo shows all three)
- For each method, show the exact configuration that would be applied:

**DNS Block example output:**
```
# DNS Blackhole — Add to internal DNS resolver
0.0.0.0 api.openai.com
0.0.0.0 chat.openai.com
0.0.0.0 *.openai.com
```

**Firewall Rule example output:**
```
Rule Name: Block-Unauthorized-AI-Tools
Action: DENY
Destination FQDN: api.openai.com, chat.openai.com
Direction: Outbound
Log: Yes
Alert: High
```

**Proxy Policy example output:**
```
Category: AI-Generative
Action: Block
Notify User: Yes
Message: "This site is restricted under company AI policy. Contact IT for approved alternatives."
```

- "Mark as Applied" button: changes tool status to "Blocked" in inventory
- "Copy to Clipboard" button: copies the configuration text
- "Close" button

---

### Action 2 — Add Monitoring

**Trigger:** User clicks "Take Action" on the Monitor card in the dashboard.

**Modal content:**
- Title: "Add AI Monitoring"
- Tools recommended for monitoring (Medium risk or Approved tools that still need visibility)
- SIEM platform selector: Splunk / Microsoft Sentinel / Generic (for demo, all show query/rule)

**Splunk SPL query example:**
```splunk
index=dns_logs
| search query IN ("openai.com", "api.openai.com", "chat.openai.com", "copilot.github.com")
| stats count by src_ip, query, _time
| eval risk="AI Tool Access - Monitor"
| table _time, src_ip, query, count, risk
```

**Microsoft Sentinel KQL example:**
```kql
DnsEvents
| where Name has_any ("openai.com", "copilot.github.com", "grammarly.com")
| summarize AccessCount=count() by ClientIP, Name, bin(TimeGenerated, 1h)
| extend RiskLabel = "Unauthorized AI Tool"
| order by AccessCount desc
```

- Alert threshold field: "Alert when a single user makes more than [N] requests in [time period]"
- "Mark as Applied" button: marks tool as Monitored in inventory
- "Copy Query" button
- "Close" button

---

## 9. Risk Scoring Logic

### Tool Risk Level

Each AI tool in the domain registry carries a base risk level: HIGH, MEDIUM, or LOW.

**HIGH risk criteria (any one of):**
- Tool sends user-input data to external AI model with no enterprise data agreement
- Tool has no enterprise/business tier with data processing agreement
- Tool is known to train on user-submitted data by default
- Tool category is generative AI with free-tier terms that allow data use

**MEDIUM risk criteria:**
- Tool has enterprise tier available with DPA but free tier in use
- Tool processes data but has published retention/deletion policy
- Tool is productivity-adjacent (writing assistance, not direct data submission)

**LOW risk criteria:**
- Tool has enterprise agreement commonly in place
- Tool does not submit user content to external models
- Tool operates entirely within enterprise tenant

### Confidence Score

| Score | Meaning |
|---|---|
| HIGH | Exact domain match against registry |
| MEDIUM | Subdomain or wildcard match |
| LOW | Pattern match (keyword in URL, not domain-specific) |

### Overall Risk Score (Dashboard)

```
Overall Score = (Tool Risk Score × 0.5) + (Assessment Gap Score × 0.5)
```

**Tool Risk Score (0–100):**
```
= 100 - ((Approved Tools / Total Tools) × 100)
  + (High Risk Tool Count × 10)
  — capped at 100
```

**Assessment Gap Score (0–100):**
```
= 100 - ((Total "Yes" points / Max possible points) × 100)
```

**Overall Rating:**
- Score 0–39: LOW risk
- Score 40–69: MEDIUM risk
- Score 70–100: HIGH risk

### NIST Function Score (per function)

```
Function Score % = (Sum of "Yes" and "Partial" points in function / Max points in function) × 100
```

---

## 10. Gap Assessment Questions

**Scoring:** Yes = 100, Partial = 50, No = 0, Unsure = 0

---

### Section 1 — Govern (4 questions)
*Does the organization have the policies and accountability structures for AI?*

| # | Question | NIST Ref |
|---|---|---|
| G1 | Does your organization have a written AI usage policy that defines approved and prohibited uses? | Govern 1.1 |
| G2 | Is there a designated owner or team responsible for AI governance decisions? | Govern 1.2 |
| G3 | Are employees required to review and acknowledge AI usage policies? | Govern 1.3 |
| G4 | Does your organization review and update AI policies at least annually? | Govern 1.7 |

**Gap findings generated by "No" answers:**
- G1 No → Finding: "No AI Usage Policy — HIGH risk. Employees have no guidance on acceptable AI use."
- G2 No → Finding: "No AI Governance Owner — MEDIUM risk. No accountable party for AI decisions."
- G3 No → Finding: "No Employee Acknowledgment — MEDIUM risk. Policy exists but is not enforced."
- G4 No → Finding: "Policies Not Reviewed — LOW risk. Governance may be outdated."

---

### Section 2 — Map (4 questions)
*Does the organization understand what AI is in use and what risks those tools carry?*

| # | Question | NIST Ref |
|---|---|---|
| M1 | Has your organization formally inventoried all AI tools in use across departments? | Map 1.1 |
| M2 | Have the data handling practices of each AI tool been reviewed? | Map 1.5 |
| M3 | Do you understand which AI tools have access to sensitive or confidential data? | Map 2.2 |
| M4 | Has a formal risk assessment been conducted for any AI tool currently in use? | Map 5.1 |

**Gap findings generated by "No" answers:**
- M1 No → Finding: "No AI Inventory — HIGH risk. Cannot manage what you cannot see."
- M2 No → Finding: "Data Practices Not Reviewed — HIGH risk. Unknown data exposure."
- M3 No → Finding: "Sensitive Data Exposure Unclear — HIGH risk. Potential regulatory violation."
- M4 No → Finding: "No Risk Assessments Conducted — MEDIUM risk. Risk posture unknown."

---

### Section 3 — Measure (4 questions)
*Does the organization actively monitor and measure AI risk over time?*

| # | Question | NIST Ref |
|---|---|---|
| ME1 | Is AI tool usage monitored in your SIEM, proxy, or equivalent system? | Measure 2.5 |
| ME2 | Do you receive alerts when new AI tools are accessed on the network? | Measure 2.6 |
| ME3 | Are AI-related incidents tracked and reviewed on a regular schedule? | Measure 4.1 |
| ME4 | Do you conduct periodic reviews of the AI inventory to check for new tools? | Measure 2.2 |

**Gap findings generated by "No" answers:**
- ME1 No → Finding: "No AI Monitoring — HIGH risk. New tools go undetected."
- ME2 No → Finding: "No New Tool Alerting — HIGH risk. Shadow AI grows undetected."
- ME3 No → Finding: "No Incident Tracking — MEDIUM risk. Patterns and trends are missed."
- ME4 No → Finding: "Inventory Not Maintained — MEDIUM risk. Inventory becomes stale quickly."

---

### Section 4 — Manage (4 questions)
*Does the organization have the processes to act on AI risk?*

| # | Question | NIST Ref |
|---|---|---|
| MG1 | Does your organization have a defined process to block or restrict unauthorized AI tools? | Manage 1.3 |
| MG2 | Is there a vendor review process for AI tools before organizational adoption? | Manage 2.2 |
| MG3 | Do you have an incident response plan that covers AI-related data exposure? | Manage 3.1 |
| MG4 | Are AI tool owners assigned to maintain accountability for each approved tool? | Manage 4.1 |

**Gap findings generated by "No" answers:**
- MG1 No → Finding: "No Block Process — HIGH risk. Cannot remediate detected risk."
- MG2 No → Finding: "No Vendor Review — HIGH risk. Tools adopted without security review."
- MG3 No → Finding: "No AI Incident Response — MEDIUM risk. No plan for data exposure events."
- MG4 No → Finding: "No Tool Owners Assigned — MEDIUM risk. No accountability for approved tools."

---

## 11. Report Specifications

### Executive Report

**Audience:** CISO, CEO, Board, General Counsel  
**Tone:** Business language, no technical jargon  
**Length:** 2–3 pages  

**Sections:**
1. Executive Summary — one paragraph, overall risk rating, top finding
2. Key Statistics — 3 numbers: tools found, gaps identified, actions recommended
3. Business Risk Summary — plain language description of top 3 risks (data exposure, legal liability, operational risk)
4. Top Decisions Required — 3 bullet points: what leadership needs to decide or fund
5. Recommended Immediate Actions — Block and Monitor, described in business terms
6. Appendix — glossary of terms used

**Does NOT include:** Log lines, domain names, NIST codes, technical remediation steps

---

### Security Report

**Audience:** Security team, IT, SOC  
**Tone:** Technical, precise, actionable  
**Length:** 5–8 pages  

**Sections:**
1. Assessment Overview — scope, log sources analyzed, date, methodology
2. Detection Summary — full tool list with domains, request counts, source IPs/users
3. Risk Findings — ranked by severity, each finding includes:
   - Finding ID (e.g., F-001)
   - Title
   - Risk Level
   - Evidence (log reference, domain, count)
   - NIST AI RMF function and sub-category
   - Recommended action with technical detail
4. Governance Gap Analysis — per NIST function scores with gap details
5. Remediation Priority List — ordered action list
6. Block Recommendations — DNS/firewall rules for high-risk tools
7. Monitoring Recommendations — SIEM queries ready for deployment

---

### Auditor Report

**Audience:** Internal and external auditors, compliance reviewers  
**Tone:** Formal, structured, evidence-referenced  
**Length:** 6–10 pages  

**Sections:**
1. Assessment Metadata — Date, scope, assessor, methodology, limitations
2. Framework Reference — Summary of NIST AI RMF functions assessed
3. Structured Findings — each finding in standardized format:
   ```
   Finding ID:        F-001
   Title:             Unauthorized AI Tool in Use — ChatGPT
   Risk Rating:       HIGH
   NIST Reference:    Map 1.1, Manage 1.3
   Evidence:          DNS log — 247 queries to api.openai.com (see Exhibit A)
   Current State:     No policy, no approval, no monitoring
   Required State:    Approved AI tools only, with signed DPA
   Gap:               Tool in use without authorization or data agreement
   Recommendation:    Block domain. Initiate vendor review for approved alternative.
   Status:            Open
   ```
4. Assessment Responses — full question-and-answer log with timestamps
5. Evidence Exhibits — log excerpts referenced in findings
6. Management Response Section — placeholder for org's formal response

---

## 12. AI Tool Domain Registry

The domain registry is a static JSON file bundled with the application. Minimum 30 entries for demo, expandable.

**Schema per entry:**
```json
{
  "id": "chatgpt",
  "name": "ChatGPT",
  "vendor": "OpenAI",
  "category": "Generative AI",
  "risk_level": "HIGH",
  "domains": ["api.openai.com", "chat.openai.com", "chatgpt.com"],
  "data_policy_url": "https://openai.com/policies/privacy-policy",
  "trains_on_data": true,
  "enterprise_tier": true,
  "enterprise_dpa": true,
  "notes": "Free tier submits data for model training. Enterprise tier with DPA available.",
  "nist_concern": "Map 1.5 — Data handling practices not reviewed"
}
```

**Minimum registry entries (demo set):**

| Tool | Risk | Category |
|---|---|---|
| ChatGPT (free) | HIGH | Generative AI |
| GitHub Copilot (free) | HIGH | Code Assistant |
| Grammarly (free) | MEDIUM | Writing |
| Notion AI | MEDIUM | Productivity |
| Google Gemini | HIGH | Generative AI |
| Claude.ai (free) | HIGH | Generative AI |
| Midjourney | HIGH | Image Generation |
| Perplexity AI | MEDIUM | Research |
| Character.ai | HIGH | Generative AI |
| Hugging Face | MEDIUM | ML Platform |
| Runway ML | HIGH | Video Generation |
| Jasper AI | MEDIUM | Writing |
| Copy.ai | MEDIUM | Writing |
| Otter.ai | HIGH | Transcription |
| Fireflies.ai | HIGH | Meeting Transcription |
| Lensa AI | HIGH | Image |
| DALL-E | HIGH | Image Generation |
| Stable Diffusion (hosted) | MEDIUM | Image Generation |
| GitHub Copilot (Enterprise) | LOW | Code Assistant |
| Microsoft Copilot (M365) | LOW | Productivity |
| Amazon CodeWhisperer | LOW | Code Assistant |
| Google Workspace AI | LOW | Productivity |

---

## 13. Sample Data Requirements

Three sample log files must be created before Step 2 can be demo'd. These are pre-built files handed to the demo user to upload.

### Sample File 1 — `sample_dns_log.txt`

**Format:** Standard BIND/syslog DNS query log  
**Detections to seed:** ChatGPT (HIGH), GitHub Copilot (HIGH), Grammarly (MEDIUM), Notion AI (MEDIUM)  
**Entry count:** ~200 lines  
**Time range:** Last 7 days  

```
2026-05-28 09:14:22 client 10.0.1.45: query api.openai.com A
2026-05-28 09:14:23 client 10.0.1.45: query api.openai.com A
2026-05-28 09:22:11 client 10.0.1.88: query copilot.github.com A
2026-05-28 10:05:44 client 10.0.1.102: query grammarly.com A
...
```

### Sample File 2 — `sample_proxy_log.csv`

**Format:** CSV with headers  
**Detections to seed:** ChatGPT, Copilot, Gemini, Perplexity  
**Headers:** `timestamp, username, destination_url, bytes_sent, bytes_received, action`  

```csv
timestamp,username,destination_url,bytes_sent,bytes_received,action
2026-05-28 09:14:22,jsmith,https://chat.openai.com/,2048,18432,ALLOWED
2026-05-28 09:22:11,mrodriguez,https://copilot.github.com/,512,4096,ALLOWED
```

### Sample File 3 — `sample_firewall_log.txt`

**Format:** Generic firewall log  
**Detections to seed:** Midjourney (HIGH), Character.ai (HIGH), Otter.ai (HIGH)  

```
May 28 11:30:22 firewall ALLOW TCP 10.0.1.55:52341 -> 162.159.134.1:443 FQDN:midjourney.com
May 28 11:45:01 firewall ALLOW TCP 10.0.1.77:49812 -> 104.21.56.89:443 FQDN:character.ai
```

**Seeded detection results (loaded from static JSON when sample files are uploaded):**

```json
{
  "scan_id": "demo-001",
  "log_entries_analyzed": 14382,
  "scan_duration_ms": 3200,
  "detected_tools": [
    {
      "tool_id": "chatgpt",
      "name": "ChatGPT",
      "domain": "api.openai.com",
      "risk_level": "HIGH",
      "confidence": "HIGH",
      "source_log": "sample_dns_log.txt",
      "users": ["10.0.1.45", "10.0.1.67", "10.0.1.102"],
      "request_count": 247,
      "first_seen": "2026-05-21 08:44:11",
      "sample_log_lines": [
        "2026-05-28 09:14:22 client 10.0.1.45: query api.openai.com A",
        "2026-05-28 09:14:23 client 10.0.1.45: query api.openai.com A",
        "2026-05-28 11:02:15 client 10.0.1.67: query api.openai.com A"
      ]
    }
  ]
}
```

---

## 14. Backend & Technical Requirements

### For Demo (MVP)

**Architecture:** Frontend-only. No server required beyond the static file server.

**Technology stack:**
- HTML / CSS / Vanilla JavaScript (consistent with landing page)
- No frontend framework required (keeps it simple and fast to build)
- `localStorage` for session state across steps
- Static JSON files for domain registry and seeded detection results
- jsPDF or browser `window.print()` for PDF export

**Files needed:**
```
/app/
  index.html ............. App shell with step navigation
  upload.html ............ Step 1
  detect.html ............ Step 2
  inventory.html ......... Step 3
  assess.html ............ Step 4
  dashboard.html ......... Step 5
  report.html ............ Step 6
  
/data/
  domain_registry.json ... AI tool domain list
  demo_results.json ...... Seeded detection results for sample files
  
/sample-logs/
  sample_dns_log.txt
  sample_proxy_log.csv
  sample_firewall_log.txt
```

### Post-Demo (Real Backend Direction)

If this product moves beyond demo, the backend would need:

- **Runtime:** Node.js with Express, or Python with FastAPI
- **Log parsing:** Per-format parsers (DNS, proxy, firewall, CloudTrail JSON)
- **Domain matching:** Domain registry loaded into memory, regex + exact match
- **Session management:** JWT or session cookie — no persistent user accounts needed initially
- **File handling:** Multer (Node) or equivalent — max 50MB per file
- **PDF generation:** Puppeteer server-side render for production-quality PDFs
- **Hosting:** Vercel, Railway, or AWS Lambda (serverless preferred for cost)
- **No database required initially** — stateless per-session architecture

---

## 15. State & Data Management

All state is stored in `localStorage` under the key `compass_session`.

**Session object structure:**

```json
{
  "session_id": "uuid",
  "created_at": "2026-06-01T10:00:00Z",
  "step_completed": 3,
  "upload": {
    "files": ["sample_dns_log.txt", "sample_proxy_log.csv"],
    "log_types": ["DNS Log", "Web Proxy Log"],
    "completed_at": "2026-06-01T10:01:00Z"
  },
  "detection": {
    "entries_analyzed": 14382,
    "tools_detected": [...],
    "completed_at": "2026-06-01T10:01:05Z"
  },
  "inventory": {
    "tools": [
      { "tool_id": "chatgpt", "review_status": "Flagged", ... }
    ],
    "completed_at": "2026-06-01T10:05:00Z"
  },
  "assessment": {
    "answers": { "G1": "No", "G2": "Partial", ... },
    "scores": { "Govern": 25, "Map": 50, "Measure": 0, "Manage": 25 },
    "gaps": [...],
    "completed_at": "2026-06-01T10:10:00Z"
  },
  "dashboard": {
    "overall_score": 78,
    "overall_rating": "HIGH",
    "actions_applied": ["block", "monitor"],
    "viewed_at": "2026-06-01T10:12:00Z"
  },
  "organization_name": "Acme Corp"
}
```

**State rules:**
- Step navigation reads `step_completed` — user cannot jump ahead
- Each step writes its data on completion
- "Start Over" clears the session object and returns to Step 1
- Session persists through page refresh (localStorage, not sessionStorage)

---

## 16. Non-Functional Requirements

| Requirement | Target |
|---|---|
| Load time | Each step page loads in under 2 seconds |
| Animation | All transitions under 400ms, no jank |
| Mobile | Responsive down to 768px (tablet minimum) |
| Browser support | Chrome, Firefox, Edge (current + 1 version behind) |
| Accessibility | Form inputs labeled, color not sole risk indicator, keyboard navigable |
| Demo reliability | App must complete full flow without errors on a demo laptop, offline |
| Data privacy note | Every step shows: "No data is stored or transmitted beyond this session" |

---

## 17. Out of Scope for MVP

- User authentication / login
- Multi-user or team collaboration
- Real-time log streaming
- SIEM API integration (Splunk, Sentinel)
- Active Directory or cloud policy push
- Vendor review workflow
- Scheduled recurring scans
- Mobile app
- Database / persistent storage
- Multi-organization support
- Custom branding / white-label

---

## 18. Success Criteria

The demo is successful if an audience member watching can answer "yes" to all of the following:

- [ ] I understand what Compass does within the first 2 minutes
- [ ] The log upload felt real and the detection result was convincing
- [ ] I can see which AI tools are highest risk and why
- [ ] I understood the governance gaps without reading the NIST framework
- [ ] The after-scan actions (Block and Monitor) gave me something concrete I could act on
- [ ] The report I saw could be sent to my leadership or auditor today
- [ ] This feels like a real product, not a class project

---

## 19. Open Questions

These must be resolved before the corresponding step can be built:

| # | Question | Blocks | Owner |
|---|---|---|---|
| OQ-1 | What format are the sample log files? Who creates them? | Step 1, Step 2 | Team |
| OQ-2 | What is the exact risk scoring formula agreed on by the team? | Step 5 | Team |
| OQ-3 | Are the Gap Assessment questions finalized? (see Section 10 for draft) | Step 4 | Team |
| OQ-4 | What does the PDF export look like — browser print or jsPDF? | Step 6 | Team |
| OQ-5 | Does each page have its own URL, or is this a single-page app? | Architecture | Team |
| OQ-6 | Is there a login screen, or does the app start directly at the upload step? | Architecture | Team |
| OQ-7 | What firewall format do we use for Block recommendations — Palo Alto, Cisco, generic? | Step 5 Action | Team |
| OQ-8 | What SIEM do we use for Monitor recommendations — Splunk, Sentinel, generic? | Step 5 Action | Team |
| OQ-9 | Who creates and provides the sample log files for the demo? | Step 2 | Team |

---

## 20. Build Priority & Phasing

### Phase 1 — Foundation (Do First)
1. Resolve all open questions (OQ-1 through OQ-9)
2. Create 3 sample log files
3. Create domain registry JSON (30+ entries)
4. Create seeded detection results JSON
5. Build app shell: navigation, step progress bar, consistent layout

### Phase 2 — Core Flow
6. Step 1: Upload UI with drag-and-drop and animation
7. Step 2: Detection results table with expandable rows
8. Step 3: Inventory table with review state management

### Phase 3 — Assessment & Intelligence
9. Step 4: Gap assessment questionnaire (all 16 questions)
10. Risk scoring engine (JavaScript functions)
11. Gap findings generator

### Phase 4 — Dashboard & Actions
12. Step 5: Dashboard with summary cards and NIST bars
13. Block action modal with configuration output
14. Monitor action modal with SIEM query output
15. Role view toggle (Executive / Security / Auditor)

### Phase 5 — Reports & Polish
16. Step 6: Three report views
17. PDF export
18. End-to-end flow test
19. Demo script rehearsal

---

*Document maintained by MICS Capstone Team. Update version number and date on each revision.*
