# Project Compass

AI Governance Assessment Platform - MICS Capstone Project

Project Compass helps IT security and compliance teams detect unsanctioned AI tool usage across their organization's network, assess governance gaps against the NIST AI Risk Management Framework, and generate audience-ready reports.

---

## Quickstart

**Prerequisites:** [Node.js](https://nodejs.org/) v18 or higher

```bash
git clone git@github.com:jrmar/Project-Compass.git
cd Project-Compass
node serve.mjs
```

Open your browser to `http://localhost:3000`

The server has no dependencies — it uses Node's built-in `http` module. No `npm install` required.

---

## Project Structure

```
Project-Compass/
├── index.html                          # Landing page
├── serve.mjs                           # Local dev server (static file server)
├── screenshot.mjs                      # Puppeteer screenshot utility
│
├── app/                                # Multi-page web application
│   ├── app.css                         # Shared styles for all app pages
│   ├── login.html                      # Step 0 - Org setup / session init
│   ├── upload.html                     # Step 1 - Upload DNS logs
│   ├── scanning.html                   # Step 1→2 - Animated analysis transition
│   ├── detect.html                     # Step 2 - Detection results (in progress)
│   ├── inventory.html                  # Step 3 - AI tool inventory (planned)
│   ├── assess.html                     # Step 4 - Gap assessment (planned)
│   ├── dashboard.html                  # Step 5 - Risk dashboard (planned)
│   └── report.html                     # Step 6 - Report generation (planned)
│
├── SampleLogs/                         # Demo log files
│   ├── sample_dns_logs.csv
│   ├── sample_firewall_logs.csv
│   └── sample_proxy_logs.csv
│
├── docs/
│   ├── PRD.md                          # Product Requirements Document
│   ├── compass_open_questions.html     # Decision brief (source)
│   └── Project_Compass_Open_Questions_v1.0.pdf
│
├── brand_assets/                       # Logos, style guides, project PDF
│
├── project_compass_ai_domain_registry_70.json          # 70-entry AI tool domain registry
├── project_compass_seeded_detection_results.json       # Raw seeded detection data
└── project_compass_seeded_detection_results_frontend.json  # Frontend-ready detection data
```

---

## Architecture

**No build system.** Vanilla HTML, CSS, and JavaScript. Each step in the workflow is a separate `.html` file. State is passed between pages using `localStorage`.

### Session State Schema

All app pages read and write a single `compass_session` key in `localStorage`:

```js
{
  org_name:   "Acme Corporation",   // set on login.html
  user_name:  "Jane Smith",         // optional
  user_role:  "IT Security",        // IT Security | Compliance | Executive | IT Admin | Other
  started_at: "2026-06-09T...",     // ISO timestamp

  upload: {
    files:       [{ name, size, rows }],  // uploaded file metadata
    uploaded_at: "2026-06-09T...",
    log_types:   ["dns"]
  },

  detection:  { /* seeded results JSON */ },   // loaded by scanning.html
  inventory:  null,                            // set by inventory.html
  assessment: null                             // set by assess.html
}
```

Any page that finds `compass_session` missing or without `org_name` redirects to `login.html`.

### Detection Strategy (Demo)

For the demo, log upload triggers predetermined results rather than a live parser. When the user clicks "Analyze Logs" on `upload.html`:

1. File metadata is saved to the session
2. `scanning.html` plays an animated analysis sequence (~5.7 seconds)
3. `scanning.html` fetches `project_compass_seeded_detection_results_frontend.json` and writes it to `session.detection`
4. The user is routed to `detect.html`

This approach lets the demo run without a backend while appearing authentic. The seeded data reflects a realistic detection scenario for a mid-size organization.

### Seeded Detection Data

13 tools detected across 5 users and 210 log events:

| Risk Level | Tools |
|---|---|
| HIGH | Unknown AI Tool, Midjourney, ElevenLabs |
| MEDIUM | Perplexity, Claude, Google Drive, Gemini, OpenAI API, ChatGPT Legacy, Unattributed SSL |
| LOW | Notion, GitHub, Microsoft Copilot |

---

## App Workflow

```
Landing Page (index.html)
        |
        | "Run Assessment"
        ↓
    login.html       ← Enter org name, role
        |
        ↓
   upload.html       ← Upload DNS log CSV (drag-and-drop)
        |
        ↓
  scanning.html      ← Animated analysis, loads seeded data
        |
        ↓
   detect.html       ← Detection results table  [IN PROGRESS]
        |
        ↓
  inventory.html     ← AI tool inventory by category  [PLANNED]
        |
        ↓
   assess.html       ← 16-question NIST gap assessment  [PLANNED]
        |
        ↓
  dashboard.html     ← Risk scores, charts  [PLANNED]
        |
        ↓
   report.html       ← Generate Executive / Security / Auditor report  [PLANNED]
```

---

## Risk Scoring

```
Overall Risk Score = (Detection Score × 50%) + (Assessment Score × 50%)

Detection Score  = weighted average of detected tool risk levels
Assessment Score = (unanswered or failed questions / total questions) × 100
```

See `docs/PRD.md` Section 9 for full scoring specification.

---

## Brand & Style

| Token | Value |
|---|---|
| Navy (background) | `#030b1e` |
| Blue (primary) | `#4082E8` |
| Teal (accent) | `#33CDB6` |
| Orange (warning) | `#FF8020` |
| Light (text) | `#D0D4E2` |

Fonts: **Montserrat** (headings) · **Inter** (body) · **JetBrains Mono** (code/logs)

Shared CSS variables and component styles live in `app/app.css`. The landing page (`index.html`) has its own inline styles to keep it self-contained.

---

## Development Notes

- Edit any `.html` or `.css` file and refresh the browser — changes are live immediately, no restart needed.
- To take a screenshot: `node screenshot.mjs http://localhost:3000 label`
- Sample DNS logs are in `SampleLogs/sample_dns_logs.csv` — use these to test the upload flow.
- To clear a session during testing, open the browser console and run `localStorage.clear()`.

---

## Docs

- [`docs/PRD.md`](docs/PRD.md) - Full product requirements (architecture, scoring, report specs, open questions)
- [`docs/Project_Compass_Open_Questions_v1.0.pdf`](docs/Project_Compass_Open_Questions_v1.0.pdf) - Decision brief with 9 architectural questions and gap assessment question bank
