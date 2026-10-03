---
title: >-
  Secrets Detection & Credential Scanning: GitLeaks, TruffleHog & Pre-Commit
  Hooks
description: A Advanced-level Product Security chapter from the Security Notebooks.
sidebar:
  order: 6
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/secure-code-review-sast-sca/06-secrets-detection-and-credential-scanning-gitleaks-trufflehog-and-pre-commit-hooks
---
The previous chapter was about the code you did not write; this one is about a specific thing that should *never* be in the code you did write: **secrets**. API keys, database passwords, cloud credentials, private keys, tokens — the credentials that grant access to real systems — end up committed to source repositories with astonishing regularity, and when they do, the consequence is direct and severe: an attacker who finds the secret has the access it grants, no exploitation required. It is Notebook 45's CWE-798 (hardcoded credentials) as an operational discipline, and it is one of the highest-frequency, highest-impact exposures in the entire field.

The reason this deserves its own chapter, rather than a line in the secure-coding chapter, is that secrets have a property no other bug class has: **git history is forever, and a deleted secret is still there.** Delete a password from a file, commit the deletion, and the password is still sitting in the previous commit, retrievable by anyone with the repository, permanently, unless you rewrite history — which is disruptive and, crucially, still does not help once the secret has been pushed to a place others have cloned. This is the single most misunderstood fact about leaked secrets, and it drives the chapter's central, counterintuitive lesson: **when a secret leaks, you rotate it — you do not merely remove it.** Scrubbing the secret from the code does not un-leak it; only invalidating the credential does.

The chapter has three movements. First, **the nature of the problem** — what secrets are, why git makes them uniquely dangerous, and how detection actually works (the regex-versus-entropy tradeoff, and the game-changing idea of *verified* detection where the tool tests whether the credential is live). Second, **the layered defense** — pre-commit hooks, CI scanning, and continuous monitoring — and why the leftmost layer, the pre-commit hook, is the highest-leverage control in the whole chapter. Third, **remediation** — the rotate-first response, why history-rewriting is a distant second, and how to prevent secrets from being written in the first place with secrets managers, because the only truly clean secret is the one that was never in the code.

## Why This Matters

Leaked secrets are consistently one of the most common initial-access vectors in real breaches, and the reason is brutal economics for the attacker: a leaked credential requires *no exploitation*. There is no vulnerability to find, no payload to craft, no defense to bypass — the attacker finds the key and *logs in*. GitHub, GitLab, and the public package registries are continuously scraped by automated bots hunting for committed AWS keys, database URLs, and API tokens, and the time-to-abuse for a public leaked cloud key is measured in *minutes* — researchers who deliberately plant canary AWS keys in public repos routinely see them used to spin up cryptomining infrastructure within an hour. The moment a secret hits a public repository, assume it is compromised, because at internet scale it already is.

The blast radius is often enormous relative to the innocuousness of the leak. A single committed cloud credential can grant access to an entire production environment; a leaked database password exposes every customer record; a leaked signing key lets an attacker forge trusted artifacts (the SolarWinds and Golden SAML lessons from Notebooks 46 and 42). And because the secret grants *legitimate* access, the intrusion often looks like normal authenticated activity, making it hard to detect after the fact — the attacker is not breaking in, they are logging in with valid credentials, which is exactly the pattern Notebook 42 Chapter 5 identified as the dominant modern attack.

The recurring lesson that this chapter exists to teach — and that costs organizations dearly when they learn it the hard way — is that **detecting the leak is the easy part; the mandatory, time-critical response is rotation.** Teams discover a committed secret, delete it from the current code, feel they have handled it, and leave the still-valid credential sitting in git history for anyone to find and use. The secret is not secured until it is *invalidated*, and every hour between leak and rotation is an hour an attacker may already be inside. Understanding this reverses the intuitive priority — code cleanup is not the fix; credential rotation is — and getting that priority right is the difference between a near-miss and a breach.

## Part 1: What Counts as a Secret, and Why They Leak

A **secret** is any credential or sensitive value that grants access or must remain confidential. The forms are more varied than "passwords," and a good detection program looks for all of them:

- **API keys and tokens** — cloud provider keys (`AKIA...` for AWS), third-party service keys (Stripe `sk_live_`, SendGrid, Twilio), OAuth tokens, personal access tokens (GitHub `ghp_`, GitLab).
- **Database and service credentials** — connection strings with embedded passwords (`postgres://user:pass@host/db`), Redis URLs, message-queue credentials.
- **Private keys** — SSH private keys, TLS private keys, PGP keys, code-signing keys (the highest-value class — the `-----BEGIN ... PRIVATE KEY-----` header is a strong detection signal).
- **Passwords** — hardcoded application passwords, service-account passwords, basic-auth credentials.
- **Cryptographic material** — symmetric keys, JWT signing secrets, encryption keys.
- **Sensitive configuration** — sometimes internal hostnames, webhook URLs with embedded tokens, or cloud account IDs, depending on threat model.

**Why do developers leak secrets?** Understanding the causes is what lets you prevent rather than merely detect. The recurring reasons:

- **Convenience under deadline.** Hardcoding a key to "just make it work" and forgetting to remove it. This is the single most common cause, and it is why the fix is making the *right* way (a secrets manager) as easy as the wrong way (Notebook 45's least-astonishment principle).
- **Committing a config or `.env` file** that was supposed to be local — the `.gitignore` missing an entry, or a `.env` added before `.gitignore` was.
- **Debugging artifacts** — a key printed to a log, pasted into a test, or dropped into a comment "temporarily."
- **Not understanding git history** — believing that deleting the secret in a later commit removes it (Part 2).
- **Secrets in places people forget to scan** — Jupyter notebooks, CI config files, Terraform state, Dockerfiles, commit messages, and issue/PR comments all hold secrets and are all frequently missed.

The prevention theme that runs through the chapter: **most secret leaks are honest mistakes by developers who had no good alternative at hand**, which means the durable fix is partly technical (detection and blocking) and partly ergonomic (making a secrets manager the path of least resistance, Part 8).

## Part 2: Why Git Makes This Uniquely Dangerous

The property that separates leaked secrets from every other bug class: **git history is permanent, and removing a secret from the current code does not remove it from history.**

```mermaid
flowchart LR
    C1[commit 1<br/>adds API_KEY=abc123] --> C2[commit 2<br/>uses it]
    C2 --> C3[commit 3<br/>DELETES the key<br/>from the file]
    C3 --> NOW[working tree:<br/>key is GONE ✓]
    C1 -.->|but the secret is STILL HERE| HIST[git history<br/>git show commit1 -> abc123<br/>FOREVER, for anyone with the repo]
    HIST -.->|and once pushed / cloned| SPREAD[on every clone, fork,<br/>CI cache, and backup]
```

The mechanics that matter:

**A deleted secret is still in history.** When you delete `API_KEY=abc123` from a file and commit, the current version of the file no longer contains it — but `git show <the-commit-that-added-it>` returns it instantly, forever. Every clone of the repository carries the full history, so every developer who ever cloned it, every fork, every CI cache, and every backup has the secret. This is why a naive "I removed the key" is not a fix.

**A working-tree scan misses history.** A tool that only scans the *current* files will not find a secret that was committed and later deleted — but that secret is still exploitable. This is why Part 5 insists you must scan **both** the working tree (to stop new leaks) *and* the full history (to find old ones), and why the two are different operations.

**Once pushed, it has escaped.** The moment a secret is pushed to a shared or public remote, it is out — cloned, cached, possibly already scraped by a bot. Rewriting history *after* a push (Part 7) removes it from the canonical repository but does *not* recall it from the clones and caches that already exist, and cannot undo the scraping that may have already happened. This is the deepest reason rotation, not removal, is the response (Part 6): you cannot make the secret un-known, so you must make it *useless*.

The consequence for the whole discipline: **treat the moment a secret is committed — not pushed, not merged, committed — as the moment it may be compromised**, and treat the moment it is *pushed to a shared remote* as the moment it *is* compromised. This is what makes the pre-commit hook (Part 4) the highest-leverage control: it is the only layer that stops the secret *before* it enters history at all, which is the only place the "history is forever" problem can be avoided rather than managed.

## Part 3: How Detection Works — Regex, Entropy, and Verification

Secrets scanners use two core detection strategies, each insufficient alone, and the best tools combine them and add a third that changes everything.

**Regex / pattern matching.** Many secrets have recognizable *formats*: AWS keys start with `AKIA` followed by 16 uppercase alphanumerics, Stripe live keys start with `sk_live_`, GitHub tokens with `ghp_`, private keys with `-----BEGIN`. A library of regexes for known credential formats catches these with high precision — when a string matches the AWS-key pattern, it very probably *is* an AWS key. The strength is precision for *known* formats; the weakness is that it misses anything without a distinctive pattern — a random database password, a custom internal token, a generic high-entropy secret has no signature to match.

**Entropy analysis.** Secrets are, by design, *random* — high entropy — while normal code and prose are low-entropy and predictable. Entropy analysis flags strings whose randomness (measured by Shannon entropy) exceeds a threshold, catching the generic secrets that regex misses — the random password, the unknown-format token. The strength is coverage of *unknown* formats; the weakness is **false positives**: hashes, UUIDs, base64-encoded data, minified code, test fixtures, and git SHAs are all high-entropy and not secrets, so pure entropy scanning is noisy.

```mermaid
flowchart TD
    STR[a string in the code] --> RX{matches a known<br/>credential regex?}
    RX -->|yes: AKIA..., sk_live_, BEGIN KEY| HIGH[high-confidence secret]
    RX -->|no| ENT{high entropy?}
    ENT -->|no| SAFE[probably not a secret]
    ENT -->|yes| MAYBE[maybe a secret<br/>-- but also hashes/UUIDs/b64<br/>-> false positives]
    HIGH --> VERIFY{VERIFIED detection:<br/>test the credential live?}
    MAYBE --> VERIFY
    VERIFY -->|responds as valid| REAL[CONFIRMED LIVE secret<br/>-> critical, rotate now]
    VERIFY -->|dead / no service| STALE[inactive -> lower priority]
```

Because each strategy alone is insufficient — regex misses unknown formats, entropy is noisy — **modern tools combine them**: regex for the known high-value formats, entropy for the generic long tail, with allowlists and context rules to suppress the obvious false positives (test files, known-dummy values).

**Verified detection — the game-changer.** The most important recent advance (TruffleHog's signature capability) is **verification**: when the tool finds a candidate credential, it *actually tests whether it is live* by making a benign authenticated request to the corresponding service. A found AWS key is tried against the AWS API; a found GitHub token against the GitHub API; a found Stripe key against Stripe. This transforms the output: instead of "here are 500 things that *look* like secrets, most of them false positives," you get "here are 7 credentials we *confirmed are live and working right now* — rotate these immediately." Verification collapses the false-positive problem for the findings that matter most and gives you an unambiguous, ranked worklist. It is the difference between a noisy scanner and an actionable one, and it is why verified detection is the capability to prioritize when choosing a tool.

## Part 4: The Layered Defense — and Why Pre-Commit Wins

Secrets scanning is deployed as *layers*, each catching what the previous one missed, and the value of a layer is inversely proportional to how late it catches the secret — because of Part 2's "history is forever," the earlier you catch it, the less irreversible damage is done.

```mermaid
flowchart LR
    DEV[developer writes code] --> PC[1. PRE-COMMIT HOOK<br/>on the dev's machine<br/>blocks the commit]
    PC --> PR[2. PRE-RECEIVE / CI<br/>on push / in the pipeline<br/>blocks the merge]
    PR --> REPO[3. REPO SCANNING<br/>continuous, full history]
    REPO --> MON[4. PLATFORM MONITORING<br/>GitHub/GitLab secret scanning<br/>+ partner rotation]
    PC -.->|secret NEVER enters history<br/>= the only reversible layer| BEST[highest leverage]
    PR -.->|secret in local history<br/>but not shared| OK
    REPO -.->|secret already in shared history<br/>-> ROTATE| LATE
    MON -.->|last line: catch what shipped| LAST
```

- **Pre-commit hook** (on the developer's machine) — runs before the commit is created, and *blocks the commit* if a secret is detected, so **the secret never enters git history at all.** This is the highest-leverage control in the chapter, because it is the *only* layer that operates before Part 2's irreversibility kicks in — the secret is caught while it is still just text in the working tree, trivially removable, never committed, never pushed, never scraped. Every other layer catches the secret *after* it is already in history somewhere and therefore already, to some degree, compromised.
- **Pre-receive hook / CI scanning** — runs on push or in the pipeline, blocking the *merge* if the developer's pre-commit hook was bypassed or not installed. This catches the secret before it reaches the shared canonical repository, but it is already in the developer's *local* history. A necessary safety net for the pre-commit layer, which developers can skip (`--no-verify`) or not have installed.
- **Repository scanning** — continuous scanning of the full history of all repositories, catching secrets that predate the program or slipped through. This finds secrets that are *already compromised* (they are in shared history), so its output feeds the rotate-first response (Part 6), not a "block."
- **Platform monitoring** — GitHub and GitLab run built-in secret scanning on pushed code, and GitHub's partner program will even *notify the service provider* (AWS, Stripe) to auto-revoke a leaked key. This is a valuable last line, but it operates *after* the push and relies on partner coverage.

The strategic point: **the earlier the layer, the more reversible the outcome.** A secret caught by the pre-commit hook is a non-event — deleted before it ever existed in history. The same secret caught by repository scanning is an *incident* — it is in shared history, presumed compromised, requiring rotation. So the program's investment priority is clear: **make the pre-commit hook ubiquitous and hard to skip**, because it is the only layer that prevents the irreversible problem rather than cleaning up after it. The later layers are essential defense-in-depth (developers forget hooks, bypass them, or use machines without them), but they are catching failures, not preventing them.

## Part 5: Scanning History vs the Working Tree

A point that follows from Part 2 but is worth isolating because it is so often gotten wrong: **you must scan two different things, and they are different operations.**

- **Working-tree scan** — scans the *current* state of the files. This is what a pre-commit hook does (the staged changes) and what a quick CI check does. It stops *new* secrets from entering. It does **not** find a secret that was committed last year and deleted last month — that secret is not in the working tree, but it is still in history and still exploitable.
- **Full-history scan** — scans *every commit ever made*, across all branches. This is what you run when *onboarding a repository* to a secrets program, because it finds the secrets that already leaked and are sitting in history waiting to be discovered. It is slower (it walks the entire commit graph) and it typically produces a backlog of historical findings that need triage and rotation.

The operational implication: **a new secrets program starts with a full-history scan of every repository** (to find and rotate the existing leaks — the backlog), and then runs **working-tree scans continuously** (pre-commit and CI) to prevent new ones. Running only the working-tree scan leaves every previously-leaked secret in place, unrotated, exploitable — the most common gap in immature programs, and exactly the gap Part 2 predicts. The lab in Part 9 does both, deliberately, to show the difference: a secret deleted from the working tree that a history scan still finds.

## Part 6: Detection Is Not Remediation — Rotate First

This is the most important operational lesson in the chapter, and the one teams most reliably get wrong. **Finding a leaked secret is not fixing it. The fix is rotation — invalidating the credential — and it comes first, before anything else.**

The reasoning is Part 2 made actionable: once a secret has been committed and (especially) pushed, you must assume it is compromised, because you cannot prove it was not seen, and at internet scale on a public repo it almost certainly was. Removing it from the code — even rewriting it out of history — does not *un-leak* it: the copies in clones, forks, caches, and the bot-scraped databases remain, and the credential is still *valid*. The only action that actually protects you is making the credential *useless*, which means **rotating it**: generating a new credential and revoking the old one at the service that issued it.

The correct remediation order:

```mermaid
flowchart TD
    FOUND[leaked secret found] --> ROTATE[1. ROTATE FIRST<br/>revoke the old credential,<br/>issue a new one at the service]
    ROTATE --> ASSESS[2. ASSESS ABUSE<br/>check the service's logs:<br/>was it used? by whom?]
    ASSESS --> REPLACE[3. REPLACE in the app<br/>via a secrets manager,<br/>not another hardcode]
    REPLACE --> SCRUB[4. optionally scrub history<br/>-- LOWEST priority,<br/>disruptive, doesn't un-leak]
    SCRUB --> PREVENT[5. prevent recurrence<br/>pre-commit hook + secrets manager]
```

1. **Rotate the credential immediately.** Revoke the leaked one, issue a replacement. This is the *only* step that actually removes the exposure, and it is time-critical — every hour counts.
2. **Assess for abuse.** Check the issuing service's access logs: was the leaked credential used, from where, to do what? This determines whether you have a leak or a full incident (Notebook 33's DFIR).
3. **Replace in the application** — deploy the new credential *properly*, via a secrets manager and environment injection (Part 8), not as another hardcode that leaks again next week.
4. **Optionally scrub history** — rewrite the secret out of git history (Part 7). This is the **lowest** priority, not the first instinct, because the secret is already rotated and therefore useless, and history rewriting is disruptive (it changes every commit hash and forces every collaborator to re-clone). Do it for hygiene and to stop the dead secret confusing future scans, but never *instead of* rotating and never *before* it.
5. **Prevent recurrence** — install the pre-commit hook and move the secret to a manager so it cannot happen again.

The one-line rule to burn in: **rotate first, scrub last.** A team that rushes to rewrite git history while leaving the valid credential live has spent effort on the disruptive, ineffective step while skipping the one that matters. The valid-but-hidden secret is the danger; the invalid-but-visible secret is harmless.

## Part 7: Removing a Secret From History (the Distant Second Step)

When you *do* scrub history — after rotating — the mechanics matter because it is disruptive and easy to do incompletely.

The tools: **`git filter-repo`** (the modern, recommended tool; `git filter-branch` is deprecated and slow) rewrites history to remove the secret from every commit that contained it. **BFG Repo-Cleaner** is a faster, simpler alternative for the common case of removing specific strings or files. Both work by rewriting every affected commit, which **changes every subsequent commit hash.**

The consequences that make it disruptive, and why it is last:

- **Every commit hash downstream of the change changes**, so the rewritten history diverges from every existing clone. Everyone who has the repository must re-clone or carefully rebase; open pull requests break; anything referencing a commit hash breaks.
- **It requires a force-push** to the shared remote, which is a heavyweight, coordinated operation on a busy repository and is often *blocked* on protected branches for good reason.
- **It does not recall the leaked secret** from the clones, forks, and caches that already exist, nor from any bot that already scraped it — which is, again, why rotation is what actually protects you and history-scrubbing is hygiene.
- **It is easy to do incompletely** — the secret may be in multiple commits, multiple branches, or tags, and a partial rewrite leaves copies behind.

The honest framing: history-scrubbing removes the *evidence* and stops the dead secret from cluttering future scans and from being *rediscovered and mistakenly treated as live*, but it does not remove the *exposure* — the exposure was removed the moment you rotated. Do it, do it completely (all branches and tags), and do it *after* the credential is already dead, so that even a leaked copy is worthless.

## Part 8: Preventing Secrets at the Source

Detection and blocking are catching a mistake; the durable fix is making the mistake unnecessary. **The only truly clean secret is the one that was never in the code**, and the way you get there is a **secrets manager** plus **environment injection.**

The pattern:

- **Store secrets in a dedicated secrets manager** — HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or a platform-native store (Notebook 45 Chapter 5's workload identity is the endgame). The secret lives there, access-controlled, audited, and rotatable centrally.
- **Inject secrets at runtime** — the application reads the secret from an environment variable or the manager's API *at startup*, and the value never appears in the source, the repository, or the build artifact. `API_KEY = os.environ["API_KEY"]` (Notebook 45 Chapter 6's fix), with the environment populated from the manager.
- **Keep local development safe** — developers use a *local* `.env` file that is **git-ignored** (and the `.gitignore` entry is itself checked and enforced), or a local secrets-manager integration, so the convenience path does not become a leak.
- **Use short-lived, dynamically-issued credentials** where possible — a secret that expires in an hour is a far smaller exposure if it leaks than a static key that works forever, and workload identity federation (Notebook 45 Chapter 7) eliminates the stored secret entirely.

The ergonomic insight that determines whether any of this works: developers leak secrets because hardcoding is the path of least resistance under deadline (Part 1). If reading from the secrets manager is *harder* than hardcoding, developers will hardcode. So the highest-leverage prevention investment is making the *right* way *easy* — a one-line SDK call, a populated environment, a template `.env.example` with placeholder values and a git-ignored real `.env` — so that the secure path is also the convenient path (Notebook 45's least-astonishment principle). A secrets program that only *blocks* leaks without also making the manager frictionless is fighting the developers; one that makes the manager the easy path is working with them.

## Part 9: Hands-On Lab — Plant, Scan, Block, and Rotate

### 9.1 What we are building

Plant secrets in a git repo, scan the working tree *and* full history (Part 5), see verified detection, install a blocking pre-commit hook (Part 4), and walk the rotate-first remediation (Part 6).

```mermaid
flowchart LR
    REPO[git repo with<br/>planted secrets] --> WT[scan working tree]
    REPO --> HIST[scan FULL HISTORY<br/>finds the deleted one]
    HIST --> HOOK[install pre-commit hook]
    HOOK --> BLOCK[new secret -> commit BLOCKED]
    BLOCK --> REM[remediate: ROTATE first,<br/>scrub last]
```

Git, Docker (for the scanners), Python 3.

### 9.2 A repo with planted secrets, including a deleted one

```bash
mkdir -p ~/secrets-lab && cd ~/secrets-lab && git init -q

# Commit 1: plant a secret.
cat > config.py <<'PY'
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_URL = "postgres://admin:sup3rs3cr3t@db.internal:5432/prod"
PY
git add config.py && git commit -q -m "add config"

# Commit 2: 'fix' it by deleting the secret -- but it stays in HISTORY (Part 2).
cat > config.py <<'PY'
import os
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_URL = os.environ["DB_URL"]
PY
git add config.py && git commit -q -m "move secrets to env (thought this fixed it)"

echo "working tree is clean:"; grep -c "AKIA" config.py

# Sample output:
# working tree is clean:
# 0
```

The working tree looks clean — the developer "fixed" it. But the secret is still in commit 1.

### 9.3 Working-tree scan vs full-history scan

```bash
# GitLeaks scanning the WORKING TREE only -- finds nothing, because the file is clean now.
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
  detect --source=/repo --no-git -v 2>/dev/null | grep -E "leaks found|no leaks"

# Sample output:
# no leaks found

# GitLeaks scanning the FULL GIT HISTORY -- finds the secret still in commit 1 (Part 5).
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
  detect --source=/repo -v 2>/dev/null | grep -E "Secret|RuleID|Commit|leaks found" | head

# Sample output (abbreviated):
# Secret:  AKIAIOSFODNN7EXAMPLE
# RuleID:  aws-access-token
# Commit:  a1b2c3d... (add config)
# 3 leaks found
```

This is Part 5's lesson in two commands: the working-tree scan says "clean," the history scan finds three secrets still sitting in commit 1. **A program that only scanned the working tree would have declared this repo safe while a live credential sat in its history.**

### 9.4 Verified detection with TruffleHog

```bash
# TruffleHog scans history AND can VERIFY whether a found credential is live (Part 3).
docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest \
  git file:///repo --only-verified 2>/dev/null | grep -E "Detector|Verified" | head

# Sample output (with a real live key, --only-verified would print it; the EXAMPLE key is not live):
# (no verified results -- the AWS EXAMPLE key is a documentation placeholder, not live)

# Without --only-verified, it reports all candidates:
docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest \
  git file:///repo 2>/dev/null | grep -cE "Found unverified result"

# Sample output:
# 3
```

The `--only-verified` flag is Part 3's game-changer: against a real repository it collapses hundreds of candidates to the handful of *live* credentials that demand immediate rotation. (Our planted key is a well-known documentation placeholder, so it verifies as not-live — which is itself the correct, useful answer.)

### 9.5 Install a blocking pre-commit hook

The highest-leverage control (Part 4) — stop the *next* secret before it enters history:

```bash
# Use GitLeaks as a pre-commit hook that BLOCKS the commit on detection.
cat > .git/hooks/pre-commit <<'HOOK'
#!/bin/sh
# Scan staged changes; block the commit if a secret is found.
if docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
     protect --staged --source=/repo -v 2>/dev/null | grep -q "leaks found"; then
  echo "COMMIT BLOCKED: a secret was detected in your staged changes."
  echo "Remove it and use a secrets manager (see Part 8). Do NOT use --no-verify."
  exit 1
fi
exit 0
HOOK
chmod +x .git/hooks/pre-commit

# Now try to commit a new secret -- the hook blocks it.
echo 'STRIPE_KEY = "sk_live_51H8xExampleABCDEFGHIJKLMNOP"' > payment.py
git add payment.py
git commit -m "add payment" 2>&1 | grep -E "BLOCKED|secret"

# Sample output:
# COMMIT BLOCKED: a secret was detected in your staged changes.
```

```bash
# Confirm the secret never entered history.
git log --oneline | wc -l    # still only the 2 earlier commits

# Sample output:
# 2
```

The secret was stopped *before* it entered git history — the only place Part 2's irreversibility can be *prevented* rather than cleaned up. This is why the pre-commit hook is the highest-leverage layer.

### 9.6 The rotate-first remediation

For the secret already in history (commit 1), follow Part 6's order:

```bash
echo "REMEDIATION for the DB_URL and AWS key found in commit 1 (Part 6 order):"
echo "1. ROTATE FIRST  -> revoke the leaked AWS key in IAM; rotate the DB password NOW."
echo "                    (this is the ONLY step that removes the exposure)"
echo "2. ASSESS        -> check CloudTrail / DB logs: was the leaked credential used?"
echo "3. REPLACE       -> issue new creds via a secrets manager (already done: env vars)."
echo "4. SCRUB (last)  -> git filter-repo to remove it from history -- AFTER rotation:"
echo "                    git filter-repo --replace-text <(echo 'AKIAIOSFODNN7EXAMPLE==>REMOVED')"
echo "5. PREVENT       -> the pre-commit hook is now installed; move to a manager."

# Sample output:
# REMEDIATION for the DB_URL and AWS key found in commit 1 (Part 6 order):
# 1. ROTATE FIRST  -> revoke the leaked AWS key in IAM; rotate the DB password NOW.
#                     (this is the ONLY step that removes the exposure)
# 2. ASSESS        -> check CloudTrail / DB logs: was the leaked credential used?
# 3. REPLACE       -> issue new creds via a secrets manager (already done: env vars).
# 4. SCRUB (last)  -> git filter-repo to remove it from history -- AFTER rotation:
#                     git filter-repo --replace-text <(echo 'AKIAIOSFODNN7EXAMPLE==>REMOVED')
# 5. PREVENT       -> the pre-commit hook is now installed; move to a manager.
```

The ordering is the entire point: **rotate first (removes the exposure), scrub last (hygiene).** A team that jumps straight to step 4 has done the disruptive, ineffective thing while leaving a live credential in the wild.

### 9.7 Extending the lab

Baseline a repo with `detect-secrets` (create a `.secrets.baseline` of accepted existing findings so only *new* secrets are flagged — the legacy-repo equivalent of Chapter 3's SAST baseline); wire GitLeaks into a GitHub Actions workflow as the CI/pre-receive layer (Part 4) so a bypassed pre-commit hook is still caught; use the `pre-commit` framework to install the hook via `.pre-commit-config.yaml` so it is shared across the team rather than living only in `.git/hooks`; and add an allowlist for a known false positive (a test fixture) to practice responsible suppression (Chapter 3 Part 7).

## Part 10: Common Pitfalls

**Deleting the secret and thinking you are done.** Git history is forever; the deleted secret is still in the previous commit and still valid. **Rotate the credential** — deletion is not remediation.

**Scrubbing history before rotating.** The disruptive, ineffective step done first while the live credential sits exposed. Rotate first, scrub last. The valid-but-hidden secret is the danger.

**Only scanning the working tree.** Misses every secret that was committed and later deleted — which are still in history and still exploitable. Full-history scan on onboarding, working-tree scan continuously.

**No pre-commit hook.** The only layer that stops a secret *before* it enters history. Every later layer is cleaning up an already-compromised secret. Make the hook ubiquitous and hard to skip.

**Pure entropy scanning with no allowlist.** Floods you with hashes, UUIDs, and base64 as false positives, and the real secret drowns (Chapter 3's noise problem again). Combine regex + entropy + allowlists, and prefer verified detection.

**Ignoring verified detection.** "500 possible secrets" is unusable; "7 confirmed-live credentials" is a worklist. Verification collapses the false-positive problem for what matters.

**Assuming a private repo is safe.** Insiders, future forks, accidental publication, and compromised accounts all reach private repos. And a private repo made public later exposes its entire history at once. Scan private repos too.

**Forgetting the non-obvious places.** Secrets hide in commit messages, CI config, Terraform state, Dockerfiles, notebooks, and issue/PR comments. Scan them.

**Blocking without providing an alternative.** If the pre-commit hook blocks the only way the developer knows to supply a credential, they will `--no-verify`. Pair blocking with a frictionless secrets manager (Part 8).

**Treating platform scanning as sufficient.** GitHub/GitLab scanning runs *after* the push — the secret is already in shared history. It is a valuable last line, not a substitute for the pre-commit hook.

## Final Revision / Summary

- Leaked **secrets** (API keys, DB credentials, private keys, tokens) are one of the most common and most damaging exposures because they require **no exploitation** — the attacker finds the credential and logs in. Public leaks are abused within *minutes* by automated scrapers.
- Git makes this uniquely dangerous: **history is forever, and a deleted secret is still there.** `git show <old-commit>` returns it; every clone, fork, and cache carries it. Treat *committed* as possibly-compromised and *pushed to a shared remote* as compromised.
- **Detection combines regex** (precise for known formats — `AKIA`, `sk_live_`, `BEGIN KEY` — but misses unknown ones) **and entropy** (catches generic random secrets but is noisy: hashes, UUIDs, base64). **Verified detection** (test whether the credential is actually live) is the game-changer, collapsing "500 maybes" into "7 confirmed-live — rotate now."
- **Layered defense**, valued by how early it catches the secret: **pre-commit hook** (blocks the commit — the *only* layer that keeps the secret out of history and thus the highest-leverage control), **pre-receive/CI** (safety net for bypassed hooks), **repository scanning** (finds already-compromised historical secrets), **platform monitoring** (last line, post-push). Earlier = more reversible.
- **Scan both the working tree** (stop new leaks) **and the full history** (find old ones) — they are different operations. A new program starts with a full-history scan of every repo (find and rotate the backlog), then runs working-tree scans continuously.
- **Detection is not remediation — rotate first.** Removing the secret from code, even from history, does not *un-leak* it (copies and scrapes remain, and the credential is still valid). The only fix is **rotating the credential** to make it useless. Order: **rotate → assess abuse → replace via a manager → scrub history (lowest priority) → prevent.** Rotate first, scrub last.
- **History scrubbing** (`git filter-repo`, BFG) is the *distant second* step: disruptive (changes every downstream hash, forces re-clones, needs a force-push), incomplete (does not recall existing clones/scrapes), and only hygiene *after* rotation has already removed the exposure.
- **Prevent at the source**: the only clean secret is one never in the code. Use a **secrets manager** + **environment injection** (`os.environ[...]`), git-ignored local `.env`, and short-lived/dynamically-issued credentials. Developers leak because hardcoding is the easy path — so **make the secrets manager the easy path**, or blocking alone will be bypassed.

## Cheat Sheet / Quick Reference

**The one rule**

```
a leaked secret is fixed by ROTATION, not by deletion.
git history is forever: git show <old-commit> returns the "deleted" secret.
committed = maybe compromised. pushed to a shared remote = compromised.
```

**Detection strategies**

```
regex   -> known formats (AKIA, sk_live_, ghp_, -----BEGIN): precise, misses unknowns
entropy -> generic random secrets: broad, noisy (hashes/UUIDs/base64 = false positives)
VERIFIED -> test if the credential is LIVE -> "7 confirmed live" beats "500 maybes"
best tools = regex + entropy + allowlists + verification
```

**Layers (earlier = more reversible)**

```
1 PRE-COMMIT HOOK  -> blocks commit; secret NEVER enters history (highest leverage)
2 pre-receive / CI -> catches bypassed hooks before the shared repo
3 repo scanning    -> finds already-compromised historical secrets -> ROTATE
4 platform scanning-> last line, post-push (GitHub/GitLab + partner auto-revoke)
```

**Scan BOTH**

```
working-tree scan -> current files (pre-commit, CI): stops NEW secrets
full-history scan -> every commit/branch (onboarding): finds OLD leaked secrets
only-working-tree = declares a repo "clean" while a live secret sits in history
```

**Remediation order (rotate first, scrub last)**

```
1. ROTATE the credential NOW        <- the ONLY step that removes the exposure
2. ASSESS abuse (service logs)
3. REPLACE via a secrets manager
4. scrub history (git filter-repo)  <- lowest priority, disruptive, doesn't un-leak
5. PREVENT (pre-commit hook + manager)
```

**Prevent at source**

```
secrets manager (Vault / AWS/Azure/GCP) + os.environ[...] injection
git-ignored local .env (+ .env.example placeholders)
short-lived / dynamically-issued creds; workload identity = no stored secret
make the manager the EASY path, or blocking gets --no-verify'd
```

**Tools**

```
GitLeaks     -> fast regex-based, great pre-commit hook + CI
TruffleHog   -> regex + entropy + VERIFIED detection (test if live)
detect-secrets -> baseline a legacy repo (flag only NEW secrets)
git filter-repo / BFG -> history rewriting (AFTER rotation)
```

## Practice Labs & Resources

**Tools and docs**
- **GitLeaks** — install as a pre-commit hook and CI step; the fast default.
- **TruffleHog** — run with `--only-verified` to experience the verification game-changer.
- **detect-secrets** (Yelp) — the baseline workflow for legacy repos.
- **git-filter-repo** and **BFG Repo-Cleaner** — for history scrubbing after rotation.
- **The `pre-commit` framework** — to share hooks across a team via `.pre-commit-config.yaml`.

**Hands-on**
- Extend the lab: baseline a repo with detect-secrets; wire GitLeaks into GitHub Actions; share the hook via the pre-commit framework; add an allowlist for a test fixture.
- Plant a *real* (throwaway) API key you control, scan with TruffleHog `--only-verified` to see it confirmed live, then rotate it and re-scan.
- Run a full-history scan against an old personal repo — most engineers find something, which is Part 5's lesson made personal.

**Deliberate practice**
- For any leaked-secret scenario, rehearse the Part 6 order out loud: rotate, assess, replace, scrub, prevent — until "rotate first" is reflex.
- Set up a secrets manager for a small project and make reading from it a one-liner, so the secure path is the easy path (Part 8).
- Audit a repo's `.gitignore` and confirm every secret-bearing file pattern (`.env`, `*.pem`, `*.key`) is covered.

**Further reading**
- GitHub and GitLab secret-scanning documentation, including GitHub's partner auto-revocation program.
- The OWASP Secrets Management Cheat Sheet.
- Notebook 45 Chapter 6 (CWE-798 and the secure-coding fix) and Chapter 5 of this notebook (dependencies — secrets also leak *into* and *out of* third-party packages).
- Chapter 7 next, which integrates secrets scanning, SAST, and SCA into the full CI/CD pipeline.
