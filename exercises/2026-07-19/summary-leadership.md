# Screening Serpens Purple Team Exercise — Leadership Briefing

**Date:** 2026-07-19 · **Audience:** Security leadership
**Ready for Claude Desktop PPTX generation.** Each `##` = one slide.

---

## Slide 1 — Title
**Purple Team Exercise: Screening Serpens (Iran-Nexus APT)**
Detection coverage validation · 2026-07-19
Threat source: Unit 42, Palo Alto Networks

## Slide 2 — The Threat
- **Screening Serpens / UNC1549** — Iran-nexus espionage group, highly active Feb–Apr 2026.
- Targets **aerospace, defense, telecom, tech** professionals via fake job offers.
- New tradecraft: disables Windows security telemetry (**AppDomainManager hijacking**) *before* malware runs — designed to defeat EDR.
- Deploys **MiniUpdate** and **MiniJunk V2** remote-access trojans.

## Slide 3 — What We Did
- Ran our threat-intel-to-detection pipeline end-to-end against this campaign.
- Extracted **24 attacker techniques**; prioritized **14** for simulation.
- Scanned endpoint logs with automated detection tooling; staged SIEM correlation.

## Slide 4 — Headline Result
- ✅ **Detection pipeline works** — caught a high-severity attack behavior (malicious PowerShell download).
- ⚠️ **Coverage is thin:** validated **~7%** of planned techniques.
- 🔴 **0 of 3 "crown-jewel" techniques** — the ones the intel says matter most — could be tested.

## Slide 5 — Why the Gap
- We only had **one type of log** available (PowerShell activity).
- The techniques that matter most for this actor leave traces in **other logs we aren't collecting** (process/module loading, scheduled tasks, security events).
- **This is a visibility gap, not a tooling failure.**

## Slide 6 — Risk in Business Terms
- If Screening Serpens targeted us today, our current logging would **miss their core intrusion techniques** (stealth code execution, disabling security monitoring, persistence).
- We would likely see delivery, but **not the compromise itself**.

## Slide 7 — Recommendations
1. **Close the visibility gap** — collect and forward endpoint process/module-load and security event logs (funding/config effort).
2. **Confirm SIEM coverage** — verify PowerShell logging is on and flowing organization-wide.
3. **Tune EDR** — flag the specific stealth techniques this actor uses as high-risk.
4. **Re-run the exercise** once the additional logs are in place to prove crown-jewel coverage.

## Slide 8 — Bottom Line
> Our detection process is sound and repeatable. The limiting factor is **log visibility**. With a focused telemetry investment, we can move from ~7% to full coverage of this actor's playbook.
