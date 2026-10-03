---
title: 'REST APIs, GraphQL & Modern API Architecture'
description: A Intermediate-level Foundations chapter from the Security Notebooks.
sidebar:
  order: 5
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/web-fundamentals/05-rest-apis-graphql-and-modern-api-architecture
---
This is Chapter 5 of the Web Fundamentals series — Notebook 6. The last two chapters were about
how the browser carries identity (sessions/tokens) and how it isolates origins (SOP/CORS). Both
increasingly serve one thing: an **API**. Modern applications are frequently a thin front-end
(a single-page app or a mobile client) talking to a back-end **API** over HTTP/JSON. The HTML
"page" is a shell; the *data and the actions* live behind API endpoints. That architectural shift
moved the security-critical surface with it. The bugs are no longer only in server-rendered
templates — they're in the authorization checks on `GET /api/users/1234`, in whether
`PATCH /api/account` lets you set fields you shouldn't, in whether a GraphQL query can ask for
data it was never meant to return.

This chapter builds the two dominant API styles — **REST** and **GraphQL** — from absolute
scratch, adds a brief tour of **gRPC** and **realtime** APIs, and then walks the **OWASP API
Security Top 10**: the specific, repeatable ways APIs get broken. If web app security in the
2000s was "find the SQL injection," API security today is "find the object the server forgot to
check you're allowed to see." That class — **Broken Object Level Authorization** — is the single
most common serious API bug in existence, and by the end of this chapter you'll test for it in
your sleep.

---

## Part 1: What an API Is, and Why the App Is Now the Client

An **API** (Application Programming Interface) is a contract that lets one program talk to another.
A **web API** exposes that contract over HTTP: a set of URLs (endpoints) that accept structured
requests and return structured responses (almost always JSON today). Instead of the server
building an HTML page, it returns *data*, and the client (browser JS, a mobile app, another
backend) decides what to do with it.

```mermaid
flowchart LR
    subgraph Client
      A[SPA / Mobile app]
    end
    subgraph Server
      B[API endpoints] --> C[(Database)]
      B --> D[Auth / business logic]
    end
    A -->|"HTTP + JSON<br/>GET /api/orders"| B
    B -->|"200 [{...}]"| A
```

This "fat client, API back-end" split has three security consequences that frame the whole
chapter:

1. **The client is untrusted and fully visible.** Anything the front-end "checks" (a hidden
   admin button, a disabled field, a client-side role check) is cosmetic. The attacker doesn't
   use your JavaScript — they call the API directly with curl or Burp. **Every** security decision
   must be enforced server-side, on the endpoint. A control that lives only in the SPA does not
   exist.

2. **The endpoints are enumerable.** The front-end's own JS reveals the API's shape — routes,
   parameter names, ID formats. Open the browser network tab and you have the API map. Attackers
   read your bundle, your Swagger/OpenAPI doc, your GraphQL introspection, and enumerate from
   there.

3. **Object IDs travel in the open.** `GET /api/invoices/8842` puts the object identifier right in
   the URL. If the server returns invoice 8842 without checking that *this caller* owns it, you
   change `8842` to `8843` and read someone else's invoice. That's BOLA/IDOR, and it's endemic
   precisely because the API design surfaces the IDs.

**The mental model for the rest of the chapter:** an API is a set of *doors* (endpoints), each
opening onto *objects* (data) and *functions* (actions). Security is entirely about whether each
door checks (a) *who* you are (authentication), (b) *whether you may open this particular door*
(function-level authz), and (c) *whether you may touch this particular object behind it*
(object-level authz). Almost every API bug is a missing one of those three checks.

---

## Part 2: REST from Scratch — Resources, Verbs, Status Codes

**REST** (Representational State Transfer) is an architectural style, not a protocol. Its core
idea: model everything as **resources** identified by URLs, and act on them with HTTP's existing
**verbs**. A resource is a noun (`/users`, `/orders/42`, `/orders/42/items`); the verb says what
to do to it.

```http
GET    /api/orders          # list orders (a collection)
POST   /api/orders          # create a new order
GET    /api/orders/42       # read one order
PUT    /api/orders/42       # replace order 42 wholesale
PATCH  /api/orders/42       # partially update order 42
DELETE /api/orders/42       # delete order 42
```

The verbs carry semantic promises (recall Chapter 2's method section):

| Verb | Meaning | Safe? | Idempotent? |
|---|---|---|---|
| `GET` | Read, no side effects | ✅ | ✅ |
| `POST` | Create / non-idempotent action | ❌ | ❌ |
| `PUT` | Replace entire resource | ❌ | ✅ |
| `PATCH` | Partial update | ❌ | ❌ (usually) |
| `DELETE` | Remove resource | ❌ | ✅ |

*Safe* = no state change; *idempotent* = doing it twice equals doing it once. These aren't just
trivia: a **state-changing `GET`** (a `GET /orders/42/cancel`) violates the "safe" promise and is
directly CSRF-able even under `SameSite=Lax` (Chapter 3). If you see actions hidden behind `GET`,
that's a design smell and often a bug.

REST leans on **HTTP status codes** to signal outcome, and the codes matter for security testing
because they're an *oracle* — they leak whether things exist and whether you're authorized:

| Code family | Meaning | Security signal |
|---|---|---|
| 2xx | Success | The action worked — did it work when it shouldn't have? |
| 400 | Bad request | Input rejected — fuzz to learn validation rules |
| 401 | Unauthenticated | "Who are you?" — no/invalid credentials |
| 403 | Forbidden | "I know you, but no" — authorization boundary |
| 404 | Not found | Resource absent — or *hidden* to avoid leaking existence |
| 429 | Too many requests | Rate limit hit — probe its bounds |
| 500 | Server error | Unhandled case — often leaks stack traces / logic |

The **401 vs 403 vs 404** distinction is a real information leak. If `GET /api/users/9999` returns
`403` for a user that exists and `404` for one that doesn't, you can *enumerate valid user IDs* by
watching the code. Well-designed APIs return a uniform `404` (or `403`) for "you can't have this,"
regardless of existence, to avoid the oracle.

**A note on "RESTful" maturity (the Richardson model).** Real APIs sit at different levels of REST
purity: Level 0 (one endpoint, everything POSTed — basically RPC over HTTP), Level 1 (resources
but one verb), Level 2 (resources + proper verbs + status codes — where most good APIs live), and
Level 3 (Level 2 + hypermedia/HATEOAS links in responses). You rarely need to police purity, but
recognizing the level tells you how to enumerate: a Level-0 "API" is a single fat endpoint with an
`action` parameter, and its bugs cluster in that parameter.

---

## Part 3: A REST Request End to End — Headers, Body, Auth

Let's make a real authenticated REST call and name every part, because each part is a place a bug
can live.

```http
POST /api/orders HTTP/1.1
Host: api.shop.com
Authorization: Bearer eyJhbGciOiJIUzI1NiI...        # who you are (Chapter 3)
Content-Type: application/json                        # body format
Accept: application/json                              # desired response format
Idempotency-Key: 3f9c-...                             # dedupe retried POSTs
X-Request-ID: ...                                     # tracing

{"productId": 551, "quantity": 2}
```

- **`Authorization: Bearer <token>`** carries identity. The server verifies it (signature, `exp`,
  audience — Chapter 3) and derives *who* is calling. Bugs: accepting an unverified token, not
  re-checking `exp`, trusting a client-supplied `X-User-Id` header instead.
- **`Content-Type: application/json`** tells the server how to parse the body. Bugs: content-type
  confusion (server parses XML → XXE; server accepts `application/x-www-form-urlencoded` and skips
  CSRF checks meant only for JSON).
- **Body as JSON** carries the parameters. Bugs: **mass assignment** (Part 8) if the server binds
  unknown fields straight onto a model; type-juggling if it coerces `"quantity": "-1"`.
- **`Idempotency-Key`** lets the client safely retry a `POST` without double-charging. Its absence
  is a reliability bug; its *presence but weak validation* can enable replay or race conditions.

A typical successful response:

```http
HTTP/1.1 201 Created
Content-Type: application/json
Location: /api/orders/9931

{"id": 9931, "productId": 551, "quantity": 2, "status": "pending", "userId": 42}
```

Notice `"userId": 42` in the response. That's **excessive data exposure** (Part 9) if the client
only needed the order status — the API returned an internal field the front-end happens to ignore,
but an attacker reading the raw response does not ignore it. APIs constantly over-return, trusting
the client to filter; the attacker never filters.

**Authentication mechanisms you'll meet on REST APIs:**

| Mechanism | How | Notes |
|---|---|---|
| Bearer token / JWT | `Authorization: Bearer <jwt>` | Most common for SPAs/mobile; see Chapter 3 |
| API key | `X-API-Key: <key>` or `?api_key=` | Static secret; key-in-URL leaks via logs |
| Session cookie | `Cookie: session=...` | Same-site web apps; needs CSRF defense |
| OAuth access token | Bearer, issued by an IdP | Delegated; validate `aud`/`scope` |
| mTLS | Client certificate | Machine-to-machine, high assurance |

---

## Part 4: GraphQL from Scratch — One Endpoint, a Typed Graph

**GraphQL** is a query language for APIs and a runtime for fulfilling those queries. It inverts
REST's model. Instead of many endpoints each returning a fixed shape, GraphQL exposes **one
endpoint** (`/graphql`) and lets the *client* specify exactly what data it wants, shaped how it
wants, in a single request.

The server publishes a **schema** — a strongly-typed graph of the data and the operations:

```graphql
type User {
  id: ID!
  name: String!
  email: String!
  orders: [Order!]!
}
type Order {
  id: ID!
  total: Float!
  items: [Item!]!
}
type Query {
  me: User
  user(id: ID!): User
  orders: [Order!]!
}
type Mutation {
  updateProfile(name: String, email: String): User
  deleteOrder(id: ID!): Boolean
}
```

The client sends a **query** (read) or **mutation** (write) asking for a precise sub-graph:

```graphql
# Request only the fields you need, and traverse relationships in one round trip
query {
  me {
    name
    orders {
      id
      total
      items { name }
    }
  }
}
```

```http
POST /graphql HTTP/1.1
Content-Type: application/json
Authorization: Bearer eyJ...

{"query": "query { me { name orders { id total } } }"}
```

The response mirrors the query's shape exactly:

```json
{ "data": { "me": { "name": "Alice", "orders": [{"id":"9931","total":42.0}] } } }
```

The wins are real: no over-fetching (ask for exactly the fields you need), no under-fetching (get
related data in one round trip instead of N REST calls), and a self-documenting typed schema. But
each of those strengths becomes an attack surface:

```mermaid
flowchart TD
    A[GraphQL strengths] --> B[Client picks fields<br/>-> excessive exposure if authz per-field missing]
    A --> C[Traverse the graph<br/>-> deep/nested queries = DoS]
    A --> D[Typed self-doc schema<br/>-> introspection maps everything]
    A --> E[One endpoint<br/>-> WAF/rate-limit rules built for REST miss it]
```

- **The client chooses fields**, so authorization can't live on the endpoint — it must live on
  *every field and object resolver*. Miss one and that field leaks.
- **The client traverses the graph arbitrarily deep** (`orders { items { product { seller {
  orders { ... } } } }`), which is a denial-of-service lever (Part 10).
- **The schema is introspectable** — by default a client can ask GraphQL to describe its entire
  schema, handing an attacker the full map (Part 10).
- **One endpoint** means REST-oriented WAF rules, per-route rate limits, and logging often don't
  understand GraphQL and miss abuse.

---

## Part 5: REST vs GraphQL vs gRPC — Choosing and Attacking Each

A quick comparative map, because the *style* determines *where the bugs are* and *how you
enumerate*.

| Dimension | REST | GraphQL | gRPC |
|---|---|---|---|
| Endpoints | Many (per resource) | One (`/graphql`) | Many (service methods) |
| Payload | JSON | JSON (typed query) | Protobuf (binary) |
| Client picks fields | No (fixed shapes) | Yes | No |
| Discovery | OpenAPI/Swagger, JS bundle | Introspection | `.proto` files / reflection |
| Over/under-fetch | Common | Solved | N/A |
| Transport | HTTP/1.1, HTTP/2 | HTTP | HTTP/2 |
| Typical bug locus | Per-endpoint authz, IDOR | Per-field authz, introspection, depth DoS | Method authz, proto fuzzing |
| Rate-limiting | Per route (easy) | Per query cost (hard) | Per method |

**gRPC in one paragraph.** gRPC is a high-performance RPC framework using **Protocol Buffers**
(a compact binary format) over HTTP/2. You define services and messages in a `.proto` file, and
tooling generates client/server stubs. It's dominant for *internal* microservice-to-microservice
traffic. Security-wise: the binary payload isn't human-readable (use `grpcurl` and the `.proto`
to interact), auth is usually mTLS or a token in metadata, and the classic bugs are missing
per-method authorization and trusting a service just because it's "internal." If you obtain the
`.proto` (or server reflection is on), you can enumerate and call methods with `grpcurl` exactly
like hitting REST endpoints.

**WebSockets / realtime** (Chapter 4's CSWSH) and **webhooks** round out modern API surfaces.
Webhooks — where a server POSTs events to a URL you registered — invert the trust direction and
bring their own bug (SSRF via the webhook URL, and forged webhook deliveries if the signature
isn't verified). We flag them here and treat SSRF fully in a later chapter.

Concretely, when a gRPC server has **reflection** enabled (common in dev, sometimes left on in
prod), `grpcurl` enumerates and calls methods with no `.proto` file at all:

```bash
# List services exposed via server reflection
grpcurl -plaintext api.internal:50051 list
# -> shop.OrderService
#    shop.AdminService        <-- an admin service you weren't supposed to see

# List methods on a service, then inspect one
grpcurl -plaintext api.internal:50051 list shop.AdminService
# -> shop.AdminService.PromoteUser

# Call a method (metadata carries the token, like Authorization in REST)
grpcurl -plaintext -H "authorization: Bearer $TOK" \
  -d '{"userId": 42}' api.internal:50051 shop.AdminService.PromoteUser
```

If `AdminService.PromoteUser` only checks that *a* token is present (not that it's an admin's),
that's BFLA over gRPC — identical bug, binary transport. Reflection-off + a leaked `.proto` gets
you the same reach via `grpcurl -proto shop.proto`.

**The practical upshot for a tester:** identify the style first, because it dictates the recon.
REST → enumerate routes (Swagger, JS, `ffuf`). GraphQL → run introspection, then reason about
per-field authz and depth. gRPC → get the `.proto`/reflection, drive with `grpcurl`.

---

## Part 6: The OWASP API Security Top 10 — The Map of API Bugs

Before the deep dives, here is the terrain. OWASP maintains a dedicated **API Security Top 10**
because API bugs differ from the classic web Top 10 — they skew heavily toward **authorization**
failures rather than injection.

| ID | Name | One-line |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | You can access objects you don't own by changing an ID |
| API2 | Broken Authentication | Weak login/token handling, credential stuffing, JWT flaws |
| API3 | Broken Object Property Level Authorization | Mass assignment + excessive data exposure (read/write the wrong fields) |
| API4 | Unrestricted Resource Consumption | No rate/size limits → DoS and cost abuse |
| API5 | Broken Function Level Authorization (BFLA) | You can call admin functions as a normal user |
| API6 | Unrestricted Access to Sensitive Business Flows | Automating a flow (buying all stock, mass signups) |
| API7 | Server-Side Request Forgery (SSRF) | API fetches an attacker-supplied URL |
| API8 | Security Misconfiguration | Debug on, verbose errors, missing headers, permissive CORS |
| API9 | Improper Inventory Management | Forgotten `/v1/` endpoints, undocumented hosts, shadow APIs |
| API10 | Unsafe Consumption of 3rd-Party APIs | Trusting upstream API data blindly |

The three that dominate real findings — and that we lab in depth — are **API1 (BOLA/IDOR)**,
**API5 (BFLA)**, and **API3 (mass assignment / excessive exposure)**. They share a root cause:
**the server authenticated you but forgot to authorize the specific object, function, or field.**
Authentication answers "who are you"; authorization answers "may you do *this*, to *that*." APIs
overwhelmingly nail the first and botch the second.

```mermaid
flowchart LR
    A[Request arrives] --> B{Authenticated?<br/>valid token}
    B -->|No| Z[401]
    B -->|Yes| C{Authorized for this<br/>FUNCTION? API5}
    C -->|No| Y[403]
    C -->|Yes| D{Authorized for this<br/>OBJECT? API1}
    D -->|No| X[403]
    D -->|Yes| E{Only the FIELDS<br/>you may see/set? API3}
    E -->|No| W[leak / mass-assign]
    E -->|Yes| OK[Safe response]
```

---

## Part 7: API1 — Broken Object Level Authorization (BOLA / IDOR)

This is the king of API bugs. **BOLA** (Broken Object Level Authorization), historically called
**IDOR** (Insecure Direct Object Reference), is when an endpoint uses a client-supplied identifier
to fetch an object but **fails to verify the caller is allowed that specific object**.

The vulnerable pattern:

```python
# VULNERABLE: fetches by id, never checks ownership
@app.route("/api/invoices/<int:iid>")
def get_invoice(iid):
    return db.invoices.find(id=iid)     # returns ANY invoice, to ANYONE authenticated
```

The attack is embarrassingly simple — change the number:

```bash
# You are authenticated as user 42, whose own invoice is 8842
curl -s https://api.shop.com/api/invoices/8842 -H "Authorization: Bearer $TOK"   # yours
curl -s https://api.shop.com/api/invoices/8843 -H "Authorization: Bearer $TOK"   # someone else's!
# -> returns invoice 8843 belonging to another user. That's BOLA.
```

The fix is one authorization check binding the object to the caller:

```python
# FIXED: the query is scoped to the authenticated user
@app.route("/api/invoices/<int:iid>")
def get_invoice(iid):
    inv = db.invoices.find(id=iid)
    if inv is None or inv.user_id != current_user.id:
        abort(404)          # 404 (not 403) so you don't leak existence
    return inv
```

**Where BOLA hides beyond the obvious:**

- **Nested/related objects:** `GET /api/orders/42/items/7` — the server checks you own order 42 but
  not that item 7 belongs to it.
- **Non-numeric IDs give false comfort.** UUIDs are *harder to guess* but not an access control —
  if a UUID leaks (in a URL, an email, another API response), the object is still readable. Never
  rely on ID unpredictability *as* authorization.
- **State-changing BOLA is worse:** `DELETE /api/comments/999` or `PATCH /api/users/1234` without
  ownership checks lets you delete or edit others' data.
- **Batch/GraphQL BOLA:** asking for `user(id: 1234)` in GraphQL is the same bug if the resolver
  doesn't check.

**Bug-bounty angle — the standard test.** Create two accounts (A and B). Do an action as B, capture
the object ID. Replay the request **as A** with B's object ID. If A gets B's data, it's BOLA. Burp's
**Autorize** and **AuthMatrix** extensions automate exactly this: they replay every request with a
low-privileged (or other-user) token and flag responses that come back `200` with data. Also try
**parameter pollution** and **type juggling** on the ID (`id=8843`, `id=8843.0`, `id[]=8843`,
`id=8843%00`) to bypass naive checks.

**Blue team detection:** BOLA shows up as a single authenticated principal accessing an unusually
wide range of object IDs, or sequential-ID sweeps. Log `(user_id, object_id, object_owner)` on
sensitive reads and alert when `user_id != object_owner` succeeds, or when one user touches many
distinct owners' objects in a short window.

---

## Part 8: API3a — Mass Assignment (Writing Fields You Shouldn't)

**Mass assignment** (a.k.a. autobinding, object injection) happens when an API takes the JSON body
and binds *all* of its fields directly onto a data model — including fields the client was never
supposed to control. The classic is a privilege field.

The vulnerable pattern (Node/Mongoose-style, but every ORM has its version):

```javascript
// VULNERABLE: spreads the whole request body onto the user model
app.patch("/api/account", (req, res) => {
  User.findByIdAndUpdate(req.user.id, { ...req.body });   // binds EVERYTHING
});
```

The API expects `{"name": "...", "email": "..."}`. The attacker sends extra fields:

```bash
curl -s -X PATCH https://api.shop.com/api/account \
  -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"name":"alice","role":"admin","emailVerified":true,"balance":999999}'
# If the model has role/emailVerified/balance and they're bound blindly -> privilege escalation
```

Now the attacker is `admin`, or has a verified email they never verified, or a fabricated balance.
Mass assignment is a *write*-side authorization failure at the property level (OWASP API3).

**How to find candidate fields:** read a `GET` response for the same object — it reveals internal
field names (`role`, `isAdmin`, `accountType`, `verified`, `ownerId`). Then try setting each via
`PATCH`/`PUT`/`POST`. GraphQL introspection or the OpenAPI schema also hand you the field list.

**The fixes:**

```javascript
// Allowlist the fields the client may set (the only robust approach)
const { name, email } = req.body;
User.findByIdAndUpdate(req.user.id, { name, email });
```

- **Allowlist** (bind only explicitly permitted fields) — not a denylist, which you'll forget to
  update when a new sensitive field is added.
- Use **separate DTOs/schemas** for input vs output so internal fields are never bindable.
- Mark sensitive attributes **non-writable** at the ORM layer (`readonly`, `guarded`/`fillable` in
  Laravel, `attr_readonly` in Rails, `exclude` in serializers).

---

## Part 9: API3b — Excessive Data Exposure (Returning Fields You Shouldn't)

The read-side twin of mass assignment. **Excessive data exposure** is when an API returns more
data than the client needs, trusting the front-end to display only the safe parts. The attacker
reads the raw response and gets the rest.

```json
// GET /api/users/42 — the UI shows only name + avatar, but the API returns:
{
  "id": 42, "name": "Alice", "avatar": "/a.png",
  "email": "alice@corp.com",          // PII the UI never shows
  "passwordHash": "$2b$12$...",        // catastrophic
  "ssn": "***-**-1234",
  "isAdmin": false,
  "internalNotes": "flagged for review"
}
```

The UI renders `name` and `avatar`; the attacker `curl`s the endpoint and harvests `email`,
`passwordHash`, `ssn`, and internal flags. This is rampant because ORMs serialize whole objects by
default (`return user` dumps every column) and developers filter in the template, not the API.

The fix mirrors Part 8: **explicit output serialization** — define exactly which fields each
response includes, per audience.

```python
# Return an explicit view, never the raw model
def public_user(u):
    return {"id": u.id, "name": u.name, "avatar": u.avatar}
```

**Bug-bounty angle:** always read the *raw* API response, not the rendered page. Diff what the UI
shows against what the JSON contains. `passwordHash`, `resetToken`, `mfaSecret`, other users'
emails, internal role flags, and soft-deleted records hiding in a list endpoint are common finds.
GraphQL makes this worse: if per-field authz is missing, you simply *ask* for the sensitive field
(`me { passwordHash }`) and see if the resolver hands it over.

---

## Part 10: GraphQL-Specific Attacks — Introspection, Depth, Batching

GraphQL's flexibility creates a distinct bug family beyond the shared authz issues.

### 10.1 Introspection — the free schema map

By default, GraphQL answers a special query describing its entire schema — every type, field,
argument, and mutation. For an attacker that's a complete map of the attack surface, including
fields the UI never uses.

```graphql
query { __schema { types { name fields { name } } } }
```

Tools like **GraphQL Voyager**, **InQL** (Burp extension), and **graphql-cog/clairvoyance** turn
introspection into a browsable graph or reconstruct the schema even when introspection is *disabled*
(by probing field suggestions in error messages). **Disable introspection in production** — but
know that disabling it is obscurity, not authorization; per-field authz must still hold.

### 10.2 Deeply nested / recursive queries — DoS

Because the client controls traversal depth, a self-referential relationship (`user → orders →
buyer → orders → ...`) lets a tiny query explode into a massive resolution tree:

```graphql
query {
  me { orders { buyer { orders { buyer { orders { buyer { name } } } } } } }
}
```

Each level multiplies the work; a few kilobytes of query can pin the database and the server —
**Unrestricted Resource Consumption** (OWASP API4). Defenses: **query depth limiting**, **query
complexity/cost analysis** (assign each field a cost, cap the total), **pagination requirements**,
and timeouts. Aliasing lets an attacker also request the *same* expensive field many times in one
query (`a: expensiveField b: expensiveField ...`), so cost analysis must count aliases.

### 10.3 Batching to bypass rate limits and brute-force

GraphQL lets a single HTTP request carry many operations (via aliases or an array of queries).
That's a rate-limit bypass and a brute-force amplifier — instead of 1000 login requests (each
rate-limited), send **one** request with 1000 aliased `login` mutations:

```graphql
mutation {
  a: login(user:"admin", pass:"pass1") { token }
  b: login(user:"admin", pass:"pass2") { token }
  c: login(user:"admin", pass:"pass3") { token }
  # ...one HTTP request, thousands of guesses
}
```

If rate limiting counts *HTTP requests* rather than *operations*, this sails past it. Defenses:
disable query batching where not needed, limit operations-per-request, and rate-limit at the
resolver/operation level, not just the HTTP level.

```mermaid
flowchart TD
    A[GraphQL endpoint] --> B[Introspection ON?] --> B1[full schema map]
    A --> C[No depth limit?] --> C1[nested query DoS]
    A --> D[Batching ON?] --> D1[rate-limit bypass / brute force]
    A --> E[No per-field authz?] --> E1[ask for sensitive field directly]
```

---

## Part 11: API5 — Broken Function Level Authorization + Other Surface

**BFLA** (Broken Function Level Authorization) is BOLA's sibling: instead of accessing an *object*
you shouldn't, you invoke a *function* (endpoint/operation) you shouldn't — typically an admin
action as a normal user.

```bash
# Normal user discovers the admin route (from JS, docs, or guessing) and just calls it
curl -s -X POST https://api.shop.com/api/admin/users/42/promote \
     -H "Authorization: Bearer $NORMAL_USER_TOK"
# If the endpoint only checks "are you logged in" and not "are you an admin" -> BFLA
```

BFLA also appears as **verb tampering** (the UI only exposes `GET /api/users/42`, but
`DELETE /api/users/42` is unprotected) and **method/endpoint guessing** (`/api/v1/admin/...`
patterns). The fix is enforcing role/permission checks on **every** function, server-side, ideally
via centralized middleware rather than per-handler `if` statements you'll forget.

**The rest of the Top 10, briefly, so the surface is complete:**

- **API2 Broken Authentication** — everything from Chapter 3 (weak tokens, no rate limit on login,
  credential stuffing, JWT `alg` flaws). APIs frequently lack lockout/rate-limits that web login
  forms have.
- **API4 Unrestricted Resource Consumption** — no pagination caps, no upload size limits, no rate
  limits → DoS and cloud-bill abuse. Test with large `?limit=100000`, huge payloads, and the
  GraphQL depth/batch tricks above.
- **API6 Unrestricted Access to Sensitive Business Flows** — the endpoint is *authorized* but the
  *flow* is automatable at scale: scalping all concert tickets, mass fake signups, coupon
  brute-forcing. Defenses are anti-automation (device fingerprinting, CAPTCHAs, per-flow limits),
  not just authz.
- **API7 SSRF** — an API that fetches a client-supplied URL (webhooks, "import from URL," PDF
  render) can be pointed at internal services / cloud metadata (`169.254.169.254`). Full treatment
  in the SSRF chapter; flag any URL-accepting parameter.
- **API8 Security Misconfiguration** — verbose errors leaking stack traces, debug endpoints,
  missing security headers, permissive CORS (Chapter 4), default creds.
- **API9 Improper Inventory Management** — old `/v1/` endpoints still live and unpatched, staging
  hosts, undocumented "shadow" APIs. Enumerate versions and hosts; the forgotten one is often the
  vulnerable one.
- **API10 Unsafe Consumption of 3rd-Party APIs** — blindly trusting data from an upstream API
  (following its redirects, rendering its HTML, deserializing its payload).

---

## Part 12: Hands-On Lab — Enumerate and Break a REST + GraphQL API

We stand up a tiny vulnerable API with both a REST and a GraphQL surface, then find BOLA, mass
assignment, excessive exposure, and GraphQL introspection. Local and safe.

### Tool from scratch: the API tester's kit

- **curl** — scriptable HTTP; your baseline.
- **Burp Suite** — intercept, Repeater (replay/modify), Intruder (fuzz IDs), and extensions
  **Autorize** (auto-tests BOLA/BFLA by replaying with another user's token) and **InQL** (GraphQL
  introspection → editable queries). Install: Burp → Extensions → BApp Store → Autorize / InQL.
- **ffuf** — content discovery for hidden routes: `ffuf -u https://api/FUZZ -w api-wordlist.txt`.
- **graphw00f / clairvoyance / InQL** — GraphQL fingerprinting and schema extraction.

### 12.1 Stand up the vulnerable API

```python
# api.py — deliberately vulnerable REST + JSON
from flask import Flask, request, jsonify, abort
app = Flask(__name__)

USERS = {1: {"id":1,"name":"alice","email":"alice@x.com","role":"user","token":"tA"},
         2: {"id":2,"name":"bob","email":"bob@x.com","role":"admin","token":"tB"}}
INVOICES = {8842:{"id":8842,"user_id":1,"amount":100},
            8843:{"id":8843,"user_id":2,"amount":9000}}

def current_user():
    tok = request.headers.get("Authorization","").removeprefix("Bearer ")
    return next((u for u in USERS.values() if u["token"]==tok), None)

@app.route("/api/invoices/<int:iid>")
def invoice(iid):
    if not current_user(): abort(401)
    return jsonify(INVOICES.get(iid) or abort(404))     # BUG: no ownership check (BOLA)

@app.route("/api/users/<int:uid>")
def user(uid):
    if not current_user(): abort(401)
    return jsonify(USERS[uid])                            # BUG: returns token/email (excessive exposure)

@app.route("/api/account", methods=["PATCH"])
def account():
    u = current_user() or abort(401)
    u.update(request.get_json())                          # BUG: mass assignment (role bindable)
    return jsonify(u)

app.run(port=5003)
```

### 12.2 Exploit BOLA

```bash
python3 api.py &
# You are alice (token tA); your invoice is 8842. Try bob's invoice 8843:
curl -s localhost:5003/api/invoices/8843 -H "Authorization: Bearer tA"
```
```json
{"amount": 9000, "id": 8843, "user_id": 2}
```
You just read another user's $9000 invoice. **BOLA confirmed.**

### 12.3 Exploit excessive data exposure

```bash
curl -s localhost:5003/api/users/2 -H "Authorization: Bearer tA"
```
```json
{"email": "bob@x.com", "id": 2, "name": "bob", "role": "admin", "token": "tB"}
```
The response leaked bob's **email** and, catastrophically, his **session token** `tB` — which you
can now replay to *become admin bob*. Excessive exposure chained into account takeover.

### 12.4 Exploit mass assignment

```bash
curl -s -X PATCH localhost:5003/api/account -H "Authorization: Bearer tA" \
  -H "Content-Type: application/json" -d '{"role":"admin"}'
```
```json
{"email": "alice@x.com", "id": 1, "name": "alice", "role": "admin", "token": "tA"}
```
Alice is now `admin` — she set a field the API never meant to expose for writing. **Mass assignment
→ privilege escalation.**

### 12.5 The fixes, side by side

```python
# BOLA fix — scope to owner:
inv = INVOICES.get(iid)
if not inv or inv["user_id"] != current_user()["id"]: abort(404)

# Excessive-exposure fix — explicit output view:
return jsonify({"id":u["id"], "name":u["name"]})

# Mass-assignment fix — allowlist writable fields:
body = request.get_json(); u["name"] = body.get("name", u["name"])
```

Re-run each attack against the fixed handlers: the invoice sweep returns `404`, the user endpoint
no longer leaks the token, and the `role` injection is ignored. Three one-line authorization checks
close three critical bugs — which is the entire lesson of API security in miniature.

---

## Part 13: Detection & Defense Angle — Building APIs That Hold

Consolidated defensive guidance across the Top 10.

**Authorization (the core):**

- Enforce **object-level** checks on every read/write: bind the object to the authenticated
  principal (`WHERE owner_id = :me`), don't just look it up by ID. Prefer scoping the *query* over
  post-hoc `if` checks.
- Enforce **function-level** checks centrally (middleware/policy layer), default-deny, so a new
  endpoint isn't public by accident.
- Enforce **property-level** control both ways: allowlist writable fields (anti mass-assignment)
  and define explicit output schemas per audience (anti excessive-exposure).
- Return uniform `404`/`403` so status codes don't become an existence oracle.

**Resource & abuse control:**

- Rate-limit per *user/token and per operation*, not just per IP/HTTP-request. For GraphQL, add
  **depth limits, complexity/cost caps, and batch limits**; disable introspection in prod.
- Cap pagination, payload, and upload sizes. Add timeouts. Add anti-automation on sensitive flows.

**Configuration & inventory:**

- Turn off debug/verbose errors in prod; strip stack traces. Set security headers; lock down CORS
  (Chapter 4). Rotate/scope API keys; never accept keys in URLs.
- Maintain an **API inventory**: know every version and host; retire old `/v1/` endpoints; scan for
  shadow APIs. API9 is a governance problem as much as a code one.

**Detection (blue team):**

```mermaid
flowchart LR
    A[API gateway + app logs] --> B{Signal?}
    B -->|One user, many owners' object IDs| C[BOLA sweep]
    B -->|Normal token hitting /admin routes| D[BFLA attempt]
    B -->|PATCH/PUT with unexpected fields| E[Mass-assignment probe]
    B -->|Huge/nested GraphQL, aliased logins| F[DoS / brute force]
    C --> G[Alert, block, revoke token]
    D --> G
    E --> G
    F --> G
```

- Log `(principal, endpoint, object_id, object_owner, decision)`; alert on authorized-but-cross-owner
  successes and on sequential-ID enumeration.
- Watch for normal-role tokens hitting admin/function endpoints (BFLA), `PATCH`/`PUT` bodies
  containing fields the schema doesn't expose (mass-assignment probing), and GraphQL queries with
  abnormal depth, size, or alias counts.
- Instrument GraphQL with per-operation cost logging so a single "one HTTP request" abuse is still
  visible as thousands of operations.

---

## Part 14: Final Revision / Summary

- Modern apps are **fat client + API back-end**. The client is untrusted and visible; **every**
  security decision must be enforced server-side on the endpoint. Endpoints and object IDs are
  enumerable by design.
- **REST** = resources (URLs) + verbs (`GET/POST/PUT/PATCH/DELETE`) + status codes. Verbs carry
  safe/idempotent promises (state-changing `GET` = smell). Status codes are an oracle: uniform
  `404`/`403` to avoid leaking existence.
- **GraphQL** = one endpoint, a typed schema, client-chosen fields via queries/mutations. Its
  strengths (field selection, graph traversal, introspection, single endpoint) are each an attack
  surface (per-field authz, depth DoS, schema mapping, WAF blind spots).
- **gRPC** = binary Protobuf over HTTP/2 for internal services; drive it with `grpcurl` + the
  `.proto`; bugs are missing per-method authz and "internal = trusted."
- The **OWASP API Security Top 10** skews toward **authorization**, not injection. The big three:
  **API1 BOLA/IDOR** (change an ID, read others' objects), **API5 BFLA** (call functions you
  shouldn't), **API3** (mass assignment writes + excessive-exposure reads). Root cause of all
  three: authenticated but not properly *authorized* for the object/function/field.
- **GraphQL-specific:** disable introspection, limit depth/complexity, limit batching (aliased
  logins bypass HTTP rate limits).
- **Fixes are small and repeatable:** scope queries to the owner, centralize function authz,
  allowlist writable fields, define explicit output views, and rate-limit per operation.

If you can look at any endpoint and immediately ask "who / which function / which object / which
fields — and is each checked server-side?", you have the API-security instinct this chapter exists
to build.

---

## Part 15: Cheat Sheet / Quick Reference

**REST verbs**

```
GET (safe,idempotent) · POST (create) · PUT (replace,idempotent) · PATCH (partial) · DELETE (idempotent)
```

**Status-code oracle:** 401=who are you · 403=no · 404=absent/hidden · 429=rate limit · 500=leak.

**OWASP API Top 10 (memorize the big 3)**

| ID | Bug | Test |
|---|---|---|
| API1 | BOLA/IDOR | change object ID, replay as other user |
| API5 | BFLA | call admin/other-verb endpoint as normal user |
| API3 | mass assign / over-expose | send extra fields; read raw response |
| API4 | resource consumption | huge limit/payload, GraphQL depth/batch |
| API7 | SSRF | point URL params at internal/metadata |

**BOLA test:** two accounts, use B's object ID as A → 200 with data = bug.

**GraphQL recon**

```graphql
query { __schema { types { name fields { name } } } }   # introspection
mutation { a: login(...) {token} b: login(...) {token} } # batch brute force
```

**Mass-assignment probe**

```bash
curl -X PATCH .../account -d '{"role":"admin","isAdmin":true,"balance":9e9}'
```

**Tooling:** Burp (Autorize=BOLA/BFLA, InQL=GraphQL, Intruder=ID fuzz) · ffuf (routes) ·
graphw00f/clairvoyance (schema) · grpcurl (gRPC).

**Defense one-liner:** authenticate once, then authorize *the object, the function, and the
fields* — every time, server-side.

---

## Part 16: Common Pitfalls

- **Trusting the client.** Hidden buttons, disabled fields, client-side role checks are cosmetic.
  Attackers call the API directly.
- **Looking up by ID without an ownership check.** The #1 API bug (BOLA). Scope the query to the
  caller.
- **Relying on UUID unpredictability as authorization.** Unguessable ≠ access-controlled; leaked
  UUIDs still work.
- **Spreading `req.body` onto a model.** Mass assignment → privilege escalation. Allowlist fields.
- **Returning the raw model.** Excessive data exposure — tokens, hashes, PII, internal flags leak.
  Serialize explicitly.
- **Status codes that leak existence.** `403` vs `404` differences enumerate valid IDs. Be uniform.
- **GraphQL introspection on in prod, no depth/complexity/batch limits.** Free schema map + DoS +
  rate-limit bypass.
- **Rate-limiting HTTP requests, not operations.** GraphQL batching and aliasing defeat per-request
  limits.
- **Function authz per-handler instead of centralized.** You'll forget one endpoint; default-deny
  middleware won't.
- **Forgotten `/v1/` endpoints and shadow/staging APIs.** API9 — the old, unpatched surface is
  often the way in.
- **State-changing `GET`s.** Violate the safe promise and are CSRF-able even under `SameSite=Lax`.

---

## Part 17: Practice Labs & Resources

- **PortSwigger Web Security Academy** — the *API testing* and *GraphQL API vulnerabilities* topics
  are the gold standard: BOLA/IDOR, mass assignment, server-side parameter pollution, GraphQL
  introspection, and depth/alias abuse labs, all browser-based and free.
- **OWASP crAPI ("completely ridiculous API")** — a purpose-built vulnerable API training app
  covering the full API Top 10 (BOLA, mass assignment, JWT, SSRF). Run it in Docker and work each.
- **VAmPI** and **DVGA (Damn Vulnerable GraphQL Application)** — small deliberately-vulnerable REST
  and GraphQL targets for BOLA, auth, and GraphQL-specific attacks.
- **OWASP Juice Shop** — has REST and some GraphQL-flavored challenges alongside the classic web
  bugs; good for chaining exposure → takeover.
- **TryHackMe / HackTheBox** — API-focused rooms/boxes (e.g. IDOR and GraphQL rooms) and web boxes
  whose foothold is an API misconfig.
- **Tooling to master:** Burp Suite with **Autorize** (BOLA/BFLA automation) and **InQL**
  (GraphQL), **Postman**/`curl` for crafting requests, **ffuf** for route discovery,
  **graphw00f**/**clairvoyance** for GraphQL fingerprint/schema, and **grpcurl** for gRPC.

**Practice questions / mini-labs to self-test:**

1. Given `GET /api/orders/1001` returning your order, describe the exact steps (two accounts, which
   requests) to prove BOLA, and write the one-line server fix.
2. A `PATCH /api/profile` accepts `{name,email}`. You suspect mass assignment. List the candidate
   fields you'd try and how you'd discover them, then write the allowlist fix.
3. A GraphQL endpoint has introspection enabled. Show the query that dumps the schema, then explain
   two distinct abuses (data and DoS) that follow.
4. Explain precisely why GraphQL query **batching** can bypass a login rate limit that a REST login
   form would enforce, and give the fix.
5. Design authorization for `DELETE /api/comments/{id}` so that it resists BOLA *and* BFLA. Name
   both checks and where they live.
