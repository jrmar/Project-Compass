# For Security Teams

Get the full technical picture: every detected AI tool, every unmet NIST control, and ready to deploy remediation steps, organized by cloud platform.

## Why Security Teams Need This

**A Summary Isn't Enough to Act On.** Knowing an organization has a governance gap doesn't tell a security team what to actually configure. Closing a gap requires the specific control, the specific tool it applies to, and the specific console steps to fix it.

**Every Platform Does It Differently.** The same control, blocking a non-compliant AI tool, looks completely different in Azure, AWS, and GCP. Generic guidance forces an engineer to translate it themselves before it's usable.

**Detection Without Enforcement Isn't Governance.** Finding shadow AI is only half the job. A security team also needs a way to actually restrict what shouldn't be running, and a record of what was blocked and why.

## What's in the Security Team Findings Report

This is the same underlying assessment used across every Compass report, upload a log, detect AI tools, answer the governance questionnaire, just formatted for a technical audience instead of a leadership or audit one.

**Assessment Summary.** Tools found, the governance risk score, the gap score, and how many of the 19 NIST controls were flagged, all in one glance.

**Full AI Tool Inventory.** Every detected tool, its domain, category, and risk tier, laid out in a single table rather than summarized away.

**NIST Function Gap Analysis.** A breakdown of points unmet and percentage met for each of the four functions, Govern, Map, Measure, and Manage, so the team can see where the organization's weakest area actually is.

**Flagged NIST Controls.** Every partially met or unmet control, with its severity and status, giving the team a prioritized worklist rather than a single score to interpret.

**DNS Block Rules.** Ready to use block lists for Pi-hole, AdGuard, and Windows DNS sinkholing, plus a Sentinel KQL query, generated directly from the tools this specific assessment detected.

**Technical Remediation Steps by Control.** Step by step configuration instructions for the highest severity gaps, written separately for Azure, AWS, and GCP, down to the specific console screen and setting.

## Frequently Asked Questions

**Is this report just a more detailed version of the Executive report?**
It's the same assessment, not a more detailed rewrite. The Executive report leads with one score and three priorities. This report keeps every control, every tool, and every remediation step intact, because a security team needs the detail an executive briefing intentionally leaves out.

**Do the remediation steps assume a specific cloud provider?**
No. Every remediation section covers Azure, AWS, and GCP separately, since the same control requires different configuration steps depending on the platform.

**Are the DNS block rules safe to deploy immediately?**
Compass generates the rules; it doesn't apply them. They're meant to go through normal change management and lab testing before reaching production DNS infrastructure, the same as any other block list.

**Where do the severity ratings on each control come from?**
Each NIST control carries a fixed severity of High, Medium, or Low, reflecting how foundational that control is to AI governance. This is separate from the risk tier assigned to each detected tool, which reflects how dangerous that particular tool could be.
