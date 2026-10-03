---
title: 'Choosing Your Path: Mapping Fields to Real Job Roles'
description: A Beginner-level Career chapter from Praneeth's cybersecurity notebook.
sidebar:
  order: 1
  label: '01 · Choosing Your Path: Mapping Fields to Real Job Roles'
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/career-mastery/01-choosing-your-path-mapping-fields-to-real-job-roles
---
**Level:** Beginner · **Track:** Career · **Read time:** 210 min

You have spent forty-three notebooks building skills. This notebook is about turning those skills into a career, and it starts with the question that quietly derails more aspiring security people than any technical gap: *what job am I actually trying to get?* "I want to work in cybersecurity" is not a goal a hiring manager can act on, because there is no such job. There are SOC analysts and penetration testers and detection engineers and application security engineers and GRC analysts and malware researchers and cloud security engineers, and those roles differ from each other as much as a surgeon differs from a pharmacist. They require different skills, attract different personalities, pay differently, and have wildly different numbers of open positions. Choosing the wrong target — or failing to choose at all — means preparing for the average of everything and being competitive for nothing.

This chapter is the map. It lays out the families of security work, the real job titles inside each, what those people actually do on a Tuesday, and — critically — which ones you can realistically be hired into first. That last qualifier matters more than any glossy list of dream jobs. Penetration testing is the most-wanted entry point and one of the least available; the SOC is the least glamorous and the widest open door. Knowing which doors are open, and matching them to your strengths rather than your fantasies, is the single most valuable career decision you will make, and it is why this is Chapter 1.

Everything downstream — which certifications to chase (Chapter 2), what to put in your portfolio (Chapter 3), how to interview (Chapter 4) — depends on the target role. Aim first. This notebook is deliberately honest, sometimes uncomfortably so, because the alternative is the motivational-poster version of security careers that leaves people confused about why "I got my certs and did the labs" did not produce a job. It produced no job because it was not aimed at one.

## Why This Matters

The cost of not choosing is invisible until it is too late. Someone who spends a year "learning cybersecurity" without a role target studies broadly, builds a scattered portfolio, and applies to a random assortment of jobs whose requirements they half-meet. They get filtered out at every stage — not because they lack ability, but because they are legible to no hiring manager. The candidate who says "I want to be a detection engineer" and can prove it beats the more talented generalist for the detection role every time, because hiring is pattern-matching against a specific need.

Choosing well also protects you from the two most common career mistakes. The first is chasing the prestige role (pentester, red teamer) that has almost no junior openings, getting rejected for a year, and concluding security "didn't work out" — when a SOC or security-engineering path would have hired them in months and led to the prestige role later anyway. The second is drifting into a role that fights your personality — a person who hates writing reports becoming a consultant, or someone who needs deep focus taking a high-interrupt SOC seat — and burning out. A career is decades long; the fit between the work and who you are compounds. Getting the target right at the start is not a nice-to-have. It is the difference between a career that builds and one that stalls.

## Part 1: Security Is Not One Career — It Is Five Families

The whole field organises into five families of work. Almost every security job is a variation within one of them.

**Offensive (Red).** Simulating attackers to find weaknesses before real ones do. Penetration testers, red teamers, exploit developers, bug bounty hunters, application security testers. The work is finding and demonstrating flaws, then explaining them. Glamorous, competitive, and — importantly — *small* at the junior level relative to its popularity.

**Defensive (Blue).** Detecting, investigating, and responding to attacks, and building the systems that do so. SOC analysts, incident responders, detection engineers, threat hunters, DFIR specialists. This is where most of the field's people and most of the entry-level openings are. The work is monitoring, triage, investigation, and building detections.

**Security Engineering / Platform.** Building and operating the security of systems: identity, cloud security, network security, security tooling and automation, DevSecOps. Security engineers and cloud security engineers. This family has boomed with cloud and is where strong software/ops skills convert directly into security careers — often the highest-paid path.

**Governance, Risk & Compliance (GRC).** Managing security as a business function: risk assessment, policy, audit, compliance (SOC 2, ISO 27001, PCI, HIPAA), vendor risk, and communicating risk to leadership. GRC analysts, auditors, risk managers, security program managers. Less technical, people- and process-heavy, and a genuine and underrated entry point (Notebook 42 covers the discipline).

**Research & Specialist.** Deep work at the frontier: vulnerability research, malware analysis/reverse engineering, cryptography, AI/ML security, hardware. Rare, senior-skewed, and usually reached *through* one of the other families rather than entered directly.

Two truths about this taxonomy. First, the families overlap and modern roles blur them (purple teaming, DevSecOps, product security). Second, the *distribution of jobs* across them is nothing like the *distribution of student interest*: interest piles onto Red and Research, while the open jobs pile onto Blue and Engineering. Aiming at where the jobs are, not where the glamour is, is the core move of this chapter.

## Part 2: The Real Job Titles and What They Actually Do

Families are abstractions; you get hired into a title. Here are the ones that matter, with the honest day-to-day.

**SOC Analyst (Blue, Tier 1/2/3).** Monitors alerts from SIEM/EDR, triages them (real incident or false positive?), investigates, and escalates. Tier 1 is high-volume alert triage; Tier 2/3 do deeper investigation and threat hunting. **The widest-open entry door in security.** Often shift-based. The complaint is alert fatigue; the reward is that you see real attacks and it is the launchpad to detection engineering, IR, and beyond. Maps to Notebooks 31–34.

**Penetration Tester (Red).** Conducts authorized assessments of apps, networks, or cloud, finds vulnerabilities, and writes reports. Most junior pentesters work at *consultancies* (many short engagements) rather than in-house. Competitive to enter; the work is 60% testing and 40% writing (people forget the writing). Maps to Notebooks 9–20.

**Application Security Engineer (Red/Engineering).** Secures software: code review, threat modeling, working with developers, running SAST/DAST, triaging bug bounty. Booming with software everywhere, and a strong path for people with dev backgrounds. Maps to Notebooks 21–27, 45–46.

**Detection Engineer (Blue/Engineering).** Builds and tunes the detections the SOC runs — writing rules (Sigma, YARA, KQL/SPL), reducing false positives, mapping coverage to MITRE ATT&CK. A rising, well-paid role, usually reached from the SOC. Maps to Notebooks 32, 34, 41.

**Security Engineer (Engineering).** The broad, high-demand, often highest-paid title: builds security into infrastructure, automates controls, manages identity and cloud security, writes tooling. Requires real software/ops competence. Cloud Security Engineer is the hot specialisation. Maps to Notebooks 37, 5, and the engineering craft.

**Incident Responder / DFIR (Blue).** Handles active incidents: containment, forensics, root-cause, recovery. Higher-stress, higher-skill; usually not a first job but reached from the SOC. Maps to Notebook 33.

**GRC Analyst / Security Analyst (GRC).** Runs risk assessments, maintains policies, prepares for audits, manages compliance and vendor risk. Underrated entry point, especially for people with business/communication strengths or coming from adjacent fields. Maps to Notebook 42.

**Threat Intelligence Analyst (Blue/Research).** Tracks threat actors, produces intelligence, supports detection and IR. Blends research and writing. Maps to Notebook 34.

**Malware Analyst / Reverse Engineer / Vulnerability Researcher (Research).** Deep technical specialists. Rarely first jobs; reached via strong reversing/pwn skill (Notebooks 35–36) and usually a stint elsewhere first.

Notice how many roles are "reached from the SOC" or "reached via another family." Security careers are *ladders and lattices*, not single leaps. The first rung is what this chapter helps you choose.

## Part 3: Seniority Ladders — Where You Actually Start

Every title has a ladder, and knowing it sets expectations and negotiation.

```
Intern / Trainee     -> learning, supervised, often the true first rung
Junior / Associate   -> the real entry level (0-2 yrs)
Mid-level            -> owns work independently (2-5 yrs)
Senior               -> owns problems and mentors (5-8 yrs)
Staff / Principal    -> owns strategy and direction (8+ yrs), IC track
Lead / Manager       -> owns people and teams (the management track)
```

Two things people get wrong. First, they aim at mid-level requirements for a first job and despair — a posting asking for OSCP + 3 years is a *mid-level* pentest role, not your target. Filter for "junior/associate/intern" explicitly. Second, they assume the only way up is management. Security has a strong **individual-contributor (IC) track** — Staff and Principal engineers who never manage people and out-earn many managers. Decide early whether you are drawn to deepening craft (IC) or leading people (management); you do not have to choose now, but knowing the fork exists changes how you plan.

## Part 4: Company Type Changes the Job More Than the Title

The same title is a different job depending on where you do it. This is one of the most under-appreciated variables.

**Startup.** You are the security team, or one of two. Enormous breadth, little depth, high autonomy, you build from scratch, and you wear every hat. Great for fast learning and ownership; risky, under-resourced, and you will be improvising. Best for generalists who thrive on ambiguity.

**Enterprise (large company).** Specialised roles, mature tooling, established processes, clear ladders, and — for a first job — structured mentorship. Slower, more process, more politics, narrower scope. The safest, most structured place to start, and where most SOC and junior openings are.

**Consultancy / MSSP.** You serve many clients. Pentest and GRC consultancies are where most *junior offensive and GRC* people actually start, because the model needs volume. You get breadth of exposure fast and you learn to write and present, but travel, billable-hour pressure, and shallow-per-client engagement are real. **If you want to be a pentester, a consultancy is usually your realistic first employer.**

**Product / Tech company.** Security *of a product* (product security, appsec) or *as a product* (a security vendor). Deep, well-paid, engineering-heavy, and requires strong software skills. Where security engineering pays the most.

**Government / Defense.** Structured, mission-driven, clearance-gated, often lower pay but high stability and unique work. Clearance is a moat that, once you have it, is a durable advantage.

The lesson: when you pick a target role, also pick a *target company type*, because "junior pentester at a consultancy" and "junior pentester in-house" are different searches with different odds. The consultancy path for offensive work, and the enterprise path for defensive work, are the highest-probability entry routes.

## Part 5: The Honest Realities — Demand, Pay, and Fit

Three realities to internalise before you choose.

**Demand is lopsided.** The "millions of unfilled security jobs" headline hides that the shortage is in *mid and senior* roles, not junior ones — and it is concentrated in Blue and Engineering, not Red. Junior offensive roles are genuinely scarce relative to applicants. Junior SOC, GRC, and security-adjacent engineering roles are far more available. Aim at availability.

**Pay varies by family and region.** As a rough shape (verify locally, and see Part 8): Security Engineering and Product Security tend to pay the most; specialised Research is high but rare; Pentest/Red is solid but not the top despite its prestige; SOC and GRC start lower but climb fast, and the SOC is a *launchpad* into higher-paying roles. In many regions the highest-leverage move is SOC or security-engineering first, then specialise upward. Absolute numbers differ enormously by country — an India entry salary and a US entry salary are not comparable, and remote work is reshaping both.

**Fit is not optional.** Match the work to who you are:

```
Like breaking things, competitive, ok with rejection & report-writing   -> Red
Like investigating, pattern-hunting, steady vigilance, teamwork         -> Blue (SOC/IR)
Like building, automating, coding, systems thinking                      -> Security Engineering
Like structure, communication, business context, writing, people        -> GRC
Like deep focus, patience, low-level detail, solitary hard problems      -> Research
```

There is no wrong family, only a wrong fit. A person forced into a mismatched role burns out regardless of skill. The best career is the intersection of *what pays and hires* and *what genuinely fits you* — and where those overlap is your target.

## Part 6: The Entry-Level Paradox and How to Break It

The universal frustration: entry-level jobs ask for experience, and you cannot get experience without a job. This is real, and it is breakable. The paradox exists because "entry-level" in security often means "entry to security, not to work" — employers want evidence you can do the job, and there are non-employment ways to provide it.

**The breakers, in order of power:**

1. **Adjacent-role pivot.** The most reliable path. IT support, helpdesk, sysadmin, network admin, or software development → security. These roles give you real infrastructure experience and an internal transfer path, and many hiring managers *prefer* security people who came up through IT/dev because they understand systems. If you are starting cold, an IT/helpdesk job is often a faster route to a security job than applying to security jobs directly.
2. **Demonstrated work in lieu of experience.** A portfolio (Chapter 3), a home lab, CTF standing, writeups, open-source contributions, a bug bounty finding. These *are* the experience for a first security role. This is why the notebook exists — the 298 chapters, the projects, the CTF record are the evidence.
3. **Internships and apprenticeships.** The intended on-ramp; treat them as the target, not the fallback. Many are convertible to full-time.
4. **The SOC and GRC doors.** As covered — the widest-open true entry points. Not a compromise; a strategic first rung.
5. **Certifications as filters-passed, not proof.** Certs (Chapter 2) mostly get you past the résumé screen; they rarely close the deal alone.

The mindset shift that breaks the paradox: stop applying as "someone with no experience" and start applying as "someone who has demonstrably done the work, just not for a paycheck yet." The portfolio, the lab, the writeups, the CTFtime profile are what make that claim true and checkable.

## Part 7: How the Notebooks Map to Roles

You have already built role-specific skill; here is the crosswalk so you can point your existing work at a target.

```
Target role              Core notebooks (skills you already have)
-----------------------  --------------------------------------------------
SOC Analyst              31 SOC, 32 Detection, 33 DFIR, 34 Threat Intel, 2 Networking
Detection Engineer       32 Detection, 34 Threat Intel, 41 Purple, 31 SOC
Incident Responder/DFIR  33 DFIR, 31 SOC, 35 Malware, 2 Networking
Penetration Tester       9-20 Pentest track, 43 CTF
Application Security      21-27 AppSec/BugBounty, 45-46 (upcoming), 5 Programming
Security Engineer         37 Cloud, 5 Programming, 1 Linux, 2 Networking, 18 AD
Cloud Security Engineer   37 Cloud, 5 Programming, 39 AI/ML (increasingly)
GRC Analyst               42 GRC & Architecture, 8 Foundations
Threat Intel Analyst      34 Threat Intel, 28 Social Eng, 10 OSINT
Malware/RE/VR             35 Malware, 36 VR/BinExp, 43 CTF (rev/pwn)
```

The practical implication: you are not starting from zero for *any* of these. Pick the target, and your existing notebook chapters become the proof-of-skill spine for that role's portfolio (Chapter 3). The gap is usually not skill — it is aim and packaging.

## Part 8: Hands-On — Build Your Role-Target Shortlist

Turn this chapter into a decision with a concrete exercise. Do it with real job postings, not from imagination.

### 8.1 The self-assessment

Answer honestly (write the answers down):

```
1. Do I prefer breaking, defending, building, governing, or researching?   (Part 5)
2. Can I tolerate report-writing and communication? How much?              (Red/GRC heavy)
3. Do I want depth (IC/specialist) or breadth+leadership (management)?      (Part 3)
4. Startup chaos or enterprise structure for my FIRST job?                  (Part 4)
5. What is my honest current strongest skill area? (which notebooks click?) (Part 7)
6. What are my constraints — region, salary floor, remote, clearance, visa?
```

### 8.2 Reality-check against live postings

Open a job board (LinkedIn, Indeed, and a security-specific board for your region) and do this, in writing:

```
- Search 3 candidate titles from Part 2 that match your self-assessment.
- Filter to "junior/associate/intern" only. Count how many exist in your region.
- Read 5 postings per title. List the RECURRING required skills and certs.
- Note: which of those do you already have (Part 7)? Which are the real gaps?
- Rank the 3 titles by (openings available) x (fit) x (skills you already have).
```

This single exercise does what no amount of reading can: it replaces your *assumption* about a role's requirements and availability with the *actual market*, in your actual region, right now. People are consistently shocked — junior pentest roles are rarer than they thought, SOC and security-engineering roles more plentiful, and the required skills different from the tutorials they were grinding.

### 8.3 Commit to a primary and a backup

```
PRIMARY TARGET:  <title> at <company type> in <region>
  Why it fits:   <from self-assessment>
  Skills I have: <notebooks/projects>
  Real gaps:     <from the postings — feeds Chapters 2 & 3>

BACKUP TARGET:   <a higher-availability adjacent role, e.g. SOC or IT->security>
  Why:           breaks the entry-level paradox if PRIMARY stalls
```

Write it down and revisit it each quarter. A primary you are aiming at, plus a higher-availability backup that keeps you employable and moving, is the strategy that actually lands a first job. Chapters 2–4 execute against this target.

### 8.4 Extending the exercise

- Do informational interviews: message three people who hold your target title (LinkedIn) and ask what their Tuesday looks like and how they got in. Fifteen minutes each; enormously clarifying.
- Track the postings for a month and watch which requirements are truly universal versus wishlist.
- Re-run 8.2 for a second region (or remote) to see how availability and pay shift.

## Part 9: Common Pitfalls

**Not choosing at all.** "Cybersecurity" is not a target. Preparing for everything makes you competitive for nothing. Pick a primary role.

**Chasing prestige over availability.** Fixating on junior pentest/red team, the scarcest junior openings, and stalling for a year. The SOC/engineering/GRC doors are open and lead upward.

**Aiming at mid-level requirements for a first job.** A posting wanting OSCP + 3 years is not entry-level. Filter for junior/associate/intern explicitly.

**Ignoring company type.** "Junior pentester in-house" barely exists; "junior pentester at a consultancy" does. Target the company type where your role hires juniors.

**Fighting your personality.** Taking a report-heavy or high-interrupt role you will hate. Fit compounds over a decades-long career.

**Treating the SOC/GRC as beneath you.** They are the widest doors and the best launchpads, not consolation prizes.

**Believing the entry-level paradox is unbreakable.** Adjacent-role pivots, portfolios, home labs, internships, and CTF records are experience. You are not "someone with no experience" — package the work you have done.

**Studying tutorials instead of the market.** The required skills for your target role are in the postings, not in the most-viewed course. Reality-check against live listings (Part 8).

## Final Revision / Summary

- Security is **not one career but five families** — Offensive (Red), Defensive (Blue), Security Engineering, GRC, and Research/Specialist — as different from each other as distinct professions.
- You are hired into a **title**, not a family: SOC analyst, penetration tester, appsec engineer, detection engineer, security engineer, DFIR, GRC analyst, threat intel, malware/RE/VR. Know the honest day-to-day of each.
- **Job distribution is nothing like student interest**: interest piles onto Red and Research; open *junior* jobs pile onto Blue, Engineering, and GRC. **Aim at availability, not glamour.**
- **Seniority ladders** run intern → junior → mid → senior → staff/principal (IC) or lead/manager. Filter first-job searches to junior/associate/intern; know the IC vs management fork.
- **Company type changes the job**: startup (breadth, chaos), enterprise (structure, most junior openings), consultancy/MSSP (where junior Red and GRC actually start), product (highest-paid engineering), government (clearance moat). Target a role *and* a company type.
- **Realities**: demand is lopsided toward mid/senior and toward Blue/Engineering; pay favours Security/Product Engineering, with SOC/GRC as fast-climbing launchpads; and **fit to your personality is not optional**.
- **The entry-level paradox is breakable**: adjacent-role pivots (IT/dev → security), demonstrated work (portfolio, home lab, CTF, writeups), internships, and the SOC/GRC doors. Apply as "someone who has done the work," not "someone with no experience."
- **Your notebooks already map to roles** — the gap is usually aim and packaging, not skill.
- The **hands-on exercise** turns this into a committed primary + backup target by reality-checking your self-assessment against live junior postings in your region — the foundation Chapters 2–4 build on.

## Cheat Sheet / Quick Reference

**Five families → fit**

```
Red (break)      : competitive, report-writing, ok with rejection
Blue (defend)    : investigate, vigilance, teamwork — WIDEST junior doors (SOC)
Engineering(build): coding, automation, systems — often highest paid
GRC (govern)     : structure, communication, business, writing — underrated door
Research (deep)  : focus, patience, low-level — rarely a first job
```

**First-job door probability (junior)**

```
HIGH : SOC analyst, GRC analyst, security-adjacent engineering, IT->security pivot
MED  : appsec (with dev background), detection engineering (from SOC)
LOW  : in-house pentest, red team, malware/RE/VR (reach these LATER)
```

**Company type for your target**

```
want pentest first  -> consultancy/MSSP
want defensive first-> enterprise SOC
want top pay eng    -> product/tech company
want ownership fast -> startup (risky)
```

**Break the paradox**: adjacent pivot · portfolio/home lab · CTF record/writeups · internship · SOC/GRC entry.

**The exercise**: self-assess → count junior openings per title in your region → rank by (openings × fit × skills you have) → commit to primary + backup.

## Practice / Resources

**Do this now**
- Complete the Part 8 exercise in writing: self-assessment, live-posting reality check, and a committed primary + backup target. Everything in Chapters 2–4 aims at it.
- Do three informational interviews with people holding your target title.

**Understand the market**
- **Job boards**: LinkedIn, Indeed, and region-specific security boards — read junior postings for your target title regularly.
- **Salary data**: levels.fyi (engineering/product), Glassdoor/Payscale, and regional surveys — verify pay for *your* region, not US headlines.
- **Role reality**: the **Cyber Career Pathways** tool (NICE/NIST framework) and community write-ups of "a day in the life" for each role.

**Community**
- Follow practitioners in your target role on LinkedIn/X and in Discord/Reddit communities; watch what they actually do and hire for.
- Notebook 43's Chapter 8 (CTF career bridge) for how competition records become portfolio evidence for these roles.

**Next in this notebook**
- Chapter 2 (Certification Roadmaps) — which certs actually matter for *your* chosen target, and which are a waste.
- Chapter 3 (Portfolio, Home Lab & CTF Plan) — building the demonstrated-work proof your target requires.
- Chapter 4 (Resume & Interviews) — landing it.

---

*Also on [Praneeth's portfolio](https://ping-praneeth.vercel.app/notebook/career-mastery/01-choosing-your-path-mapping-fields-to-real-job-roles), with comments and the latest edits.*
