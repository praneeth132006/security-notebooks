---
title: 'Asymmetric Encryption: RSA, ECC & Diffie-Hellman Key Exchange'
description: A Intermediate-level Cryptography chapter from the Security Notebooks.
sidebar:
  order: 3
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/cryptography/03-asymmetric-encryption-rsa-ecc-and-diffie-hellman-key
---
This is Chapter 3 of the Cryptography series — Notebook 7. Chapter 2 built fast, practical
confidentiality with symmetric ciphers, but left one problem wide open: **how do two parties who
have never met agree on a shared secret key over an insecure channel?** If Alice and Bob both need
the *same* AES key, someone has to deliver it — and any eavesdropper on that delivery gets the key
and reads everything. That is the **key-distribution problem**, and for all of history it was solved
by trusted couriers and pre-shared secrets. In the 1970s, **public-key (asymmetric) cryptography**
solved it with mathematics, and the modern internet became possible.

The core idea is almost magical: a **key pair** where the two keys are different — a **public key**
you can shout to the world, and a **private key** you never reveal. What one key locks, only the
other unlocks. Publish your public key; anyone can encrypt to you, but only your private key
decrypts. Or sign with your private key; anyone can verify with your public key, but only you could
have produced the signature. Asymmetric crypto delivers **key exchange**, **encryption without a
shared secret**, and **digital signatures** — the three things symmetric crypto cannot do alone.

This chapter builds the three pillars — **RSA**, **elliptic-curve cryptography (ECC)**, and
**Diffie-Hellman key exchange** — from their underlying one-way math, through real key generation
and correct usage, to the attacks that break them when misused. As with Chapter 2, the algorithms
themselves are strong; the vulnerabilities live in **padding, key sizes, randomness, and parameter
validation**. Textbook RSA, PKCS#1 v1.5, reused ECDSA nonces, and unvalidated curve points have all
caused real, catastrophic breaks — and by the end you'll recognize each on sight.

---

## Part 1: The Key-Distribution Problem and the Public-Key Idea

Symmetric crypto's fatal limitation for open networks: both sides need the *same* secret key, but
establishing it requires a secure channel — which is the very thing you're trying to build. With *n*
people who all want to talk privately, you also need *n(n−1)/2* pre-shared keys (a thousand people →
half a million keys). It doesn't scale, and it can't bootstrap over the open internet.

**Asymmetric cryptography** breaks the symmetry. Each party generates a **key pair**:

- a **public key** — published freely, used to *encrypt to you* or *verify your signatures*;
- a **private key** — kept secret forever, used to *decrypt* or *sign*.

The keys are mathematically linked but you **cannot feasibly derive the private key from the
public key**. That asymmetry is the whole game.

```mermaid
flowchart LR
    subgraph Bob
      BPub[Bob PUBLIC key<br/>published] 
      BPriv[Bob PRIVATE key<br/>secret]
    end
    A[Alice] -->|encrypt with Bob's PUBLIC key| CT[ciphertext]
    CT -->|only Bob's PRIVATE key decrypts| BPriv
    BPub -.anyone can have it.-> A
```

This single idea delivers three capabilities symmetric crypto can't:

| Capability | How | Chapter |
|---|---|---|
| **Key exchange** | agree a shared secret over a public channel (DH/ECDH) | this ch. Part 8 |
| **Encryption without pre-shared key** | encrypt with recipient's public key (RSA-OAEP, ECIES) | this ch. Parts 3–7 |
| **Digital signatures** | sign with private key, verify with public (RSA/ECDSA/EdDSA) | Chapter 6 |

But asymmetric crypto is **slow** — orders of magnitude slower than AES — so it is almost never used
to encrypt bulk data. Instead it does the *small, hard* job (agree or deliver a symmetric key,
sign a hash) and hands the bulk work to symmetric crypto. That's **hybrid encryption** (Chapter 1):
RSA/ECDH protects the little AES key; AES protects the gigabytes. Every TLS handshake works exactly
this way.

---

## Part 2: One-Way Functions and Trapdoors — The Math Underneath

Public-key crypto rests on **trapdoor one-way functions**: easy to compute forward, infeasible to
reverse — *unless* you know a secret "trapdoor," which makes reversing easy. The public key defines
the forward function; the private key is the trapdoor.

Three hard problems power essentially all deployed asymmetric crypto:

| Hard problem | "Easy forward" | "Hard reverse" | Powers |
|---|---|---|---|
| **Integer factorization** | multiply two big primes p·q = n | factor n back into p, q | RSA |
| **Discrete logarithm (DLP)** | compute gˣ mod p | find x from gˣ | classic Diffie-Hellman, DSA |
| **Elliptic-curve DLP (ECDLP)** | compute x·G (point mult) | find x from x·G | ECC, ECDH, ECDSA, EdDSA |

The asymmetry in difficulty is enormous. Multiplying two 1024-bit primes is instant; **factoring**
the 2048-bit product is beyond all current computing for the lifetime of the universe. Computing
`g^x mod p` is fast; recovering `x` (the **discrete log**) is infeasible for large `p`. These gaps
*are* the security.

```mermaid
flowchart LR
    P[two big primes p, q] -->|multiply: EASY| N[modulus n = p*q]
    N -.factor: INFEASIBLE.-> P
    K[private key = trapdoor<br/>knows p, q] -->|makes reverse easy| N
```

Two crucial consequences you must carry forward:

- **These problems have different strengths per bit.** Factoring and classic DLP have sub-exponential
  attacks (the number field sieve), so RSA/DH need *huge* keys (2048–4096 bits) for 112–128-bit
  security. ECDLP has only *fully exponential* known attacks, so ECC gets the same security from a
  *tiny* key (256 bits). This is why **256-bit ECC ≈ 3072-bit RSA** (Chapter 1's table).
- **Quantum computers threaten all three.** **Shor's algorithm** would efficiently factor and solve
  discrete logs, breaking RSA, DH, and ECC entirely. This is the driver behind **post-quantum
  cryptography** (Part 11). Symmetric crypto and hashes are only mildly weakened (Grover), which is
  why the quantum threat lands hardest on *this* chapter's primitives.

---

## Part 3: RSA from Scratch — Key Generation and Math

**RSA** (Rivest–Shamir–Adleman, 1977) is the classic public-key system, built on factoring. Here is
the entire algorithm, which you should understand end to end at least once.

**Key generation:**

1. Choose two large random primes `p` and `q` (each ~1024 bits for a 2048-bit key).
2. Compute the modulus `n = p · q` (this is public).
3. Compute Euler's totient `φ(n) = (p−1)(q−1)`.
4. Choose a public exponent `e` coprime to `φ(n)` — almost always **65537** (`0x10001`).
5. Compute the private exponent `d = e⁻¹ mod φ(n)` (the modular inverse of e).

The **public key** is `(n, e)`; the **private key** is `(n, d)` (with `p, q` kept for speed). The
trapdoor is that computing `d` requires `φ(n)`, which requires factoring `n` — infeasible without
`p, q`.

**Encryption / decryption** (for a message `m` as a number `0 ≤ m < n`):

```
ciphertext:  c = m^e mod n        (anyone, with the public key)
plaintext:   m = c^d mod n        (only the holder of d)
```

It works because of Euler's theorem: `(m^e)^d = m^(ed) ≡ m (mod n)` since `ed ≡ 1 (mod φ(n))`.
**Signing is the same math with the keys swapped**: sign with `d`, verify with `e` (Chapter 6).

**The two directions of one keypair (encryption vs signature).** RSA is symmetric in its keys —
either exponent "undoes" the other — so the *same* keypair does two opposite jobs, and confusing them
is a common conceptual error:

```mermaid
flowchart LR
    subgraph "Encryption (confidentiality)"
      A1[anyone] -->|encrypt with PUBLIC key| B1[ciphertext] -->|decrypt with PRIVATE key| C1[only you read it]
    end
    subgraph "Signature (authenticity)"
      A2[you] -->|sign with PRIVATE key| B2[signature] -->|verify with PUBLIC key| C2[anyone confirms it's you]
    end
```

*Encrypt with the recipient's **public** key* (secrecy — only they decrypt). *Sign with your **own
private** key* (authenticity — anyone verifies). Public-to-encrypt, private-to-sign — memorize the
direction and half of applied public-key crypto stops being confusing. (Signatures get full
treatment in Chapter 6; here just fix the direction.)

A tiny, illustrative (insecure — small numbers) worked example:

```python
# TOY RSA to see the mechanism (NEVER use small primes in reality)
p, q = 61, 53
n = p * q                      # 3233
phi = (p-1) * (q-1)            # 3120
e = 17                         # coprime to phi
d = pow(e, -1, phi)            # 2753  (modular inverse)

m = 65                         # message as a number
c = pow(m, e, n)              # 2790  encrypt with (n, e)
back = pow(c, d, n)          # 65    decrypt with (n, d)
print(c, back)                # 2790 65
```

Generate a *real* keypair with OpenSSL and inspect it:

```bash
openssl genrsa -out priv.pem 2048           # generate 2048-bit private key
openssl rsa -in priv.pem -pubout -out pub.pem   # extract the public key
openssl rsa -in priv.pem -text -noout | head   # see n (modulus), e, d, primes
# publicExponent: 65537 (0x10001)   <- the ubiquitous e
```

---

## Part 4: Why "Textbook RSA" Is Broken — Padding Matters

The math above is **textbook (raw) RSA**, and using it directly is dangerous. Raw RSA is
**deterministic** (same plaintext → same ciphertext, so it leaks equality and is chosen-plaintext
guessable) and **malleable** (algebraic structure attackers exploit). Real RSA must use a **padding
scheme** that adds randomness and structure. The history of RSA padding is a history of attacks.

### Textbook-RSA attacks (why raw is unusable)

- **Deterministic → dictionary/guessing.** Encrypting a small set of possible messages (yes/no, a
  4-digit PIN) lets an attacker encrypt every candidate with the public key and match ciphertexts.
- **Small-`e` / low-exponent attack.** If `e = 3` and the message is small enough that `m^3 < n`,
  then `c = m^3` with *no modular reduction*, and the attacker just takes the **integer cube root**
  of `c` to recover `m` — no factoring needed.

```python
# Small-e attack on textbook RSA when m^3 < n
import gmpy2
c = m3 = 65**3                 # e=3, tiny message, no wraparound
m = int(gmpy2.iroot(c, 3)[0])  # integer cube root -> recovers 65
```

- **Håstad's broadcast attack.** The same message sent to `e` recipients (with `e=3`, three
  different moduli) is recoverable via the Chinese Remainder Theorem + cube root.
- **Common-modulus attack.** Two users sharing the same `n` but different `e` values leak each
  other's messages (and the shared `n` can be factored from two key pairs).
- **Malleability.** `c^k` decrypts to `m·(something)` — an attacker can transform ciphertext into a
  *related* ciphertext, breaking naive signature/encryption schemes.

### The padding schemes

| Scheme | Use | Status |
|---|---|---|
| Textbook / raw RSA | none | **broken** — deterministic, malleable |
| **PKCS#1 v1.5** (encryption) | legacy TLS/apps | **vulnerable** — Bleichenbacher padding oracle |
| **OAEP** (RSA-OAEP) | encryption | **current** — randomized, provably secure padding |
| **PKCS#1 v1.5** (signatures) | legacy | avoid — implementation bugs (Part 5) |
| **PSS** (RSA-PSS) | signatures | **current** — randomized signature padding |

### More key-parameter attacks (why you don't pick your own RSA parameters)

- **Wiener's attack (small `d`).** Choosing a *small* private exponent `d` for faster decryption is
  fatal: if `d < n^0.25`, `d` is recoverable from the public `(n, e)` via **continued fractions** —
  no factoring needed. (This is the mirror of small-`e`: small `e` is fine *with padding*; small `d`
  is never fine.)
- **Coppersmith / partial-key exposure.** If an attacker learns *part* of `p`, or a chunk of the
  plaintext is known, **Coppersmith's method** (lattice reduction) can recover the rest. Leaking even
  ~half the bits of a prime, or the high bits of `d`, can be enough to factor `n`.
- **Fermat factorization (close primes).** If `p` and `q` are too *close* together (a real bug in
  some libraries' keygen), `n` factors almost instantly by searching near `√n`. Primes must be
  independently random, not adjacent.

The unifying point: RSA has a **minefield of parameter choices** (`e`, `d`, prime generation,
padding) where a "reasonable-looking" shortcut is catastrophic. This is the strongest argument for
**never generating or implementing RSA yourself** — use a vetted library that picks all of these
correctly.

**The rule:** for encryption use **RSA-OAEP**; for signatures use **RSA-PSS**. Never raw RSA, and
migrate off PKCS#1 v1.5 encryption.

```bash
# Encrypt with OAEP (correct), not raw
openssl pkeyutl -encrypt -pubin -inkey pub.pem -pkeyopt rsa_padding_mode:oaep \
  -in secret.txt -out secret.enc
openssl pkeyutl -decrypt -inkey priv.pem -pkeyopt rsa_padding_mode:oaep \
  -in secret.enc -out out.txt
```

---

## Part 5: The Bleichenbacher Attack and RSA Signature Bugs

**PKCS#1 v1.5 encryption padding** enabled one of the most famous crypto attacks — Bleichenbacher's
1998 **"million-message attack"**, still breaking systems 25 years later (ROBOT, 2017; and TLS
implementations repeatedly).

### The Bleichenbacher padding oracle

Like CBC's padding oracle (Chapter 2), it needs only a server that reveals whether decrypted
ciphertext has **valid PKCS#1 v1.5 padding** (via an error, timing, or behavioral difference). Using
RSA's malleability, the attacker sends many carefully-multiplied ciphertexts; each "valid padding"
answer narrows the possible plaintext, until — after ~millions of queries — they recover the
plaintext (often the TLS pre-master secret) **without the private key**.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant S as Server (PKCS#1 v1.5 oracle)
    A->>S: send c * s^e mod n  (malleated ciphertext)
    S-->>A: "valid padding" / "invalid"
    Note over A: each answer narrows the plaintext interval
    A->>A: adaptively choose next s (Bleichenbacher's algorithm)
    Note over A: after ~10^6 queries -> full plaintext (e.g. TLS pre-master secret)
```

**Fixes:** use **OAEP** (not v1.5), and make padding-check failures **indistinguishable** (constant
time, identical behavior) — the same "don't leak *why* it failed" lesson as CBC. TLS 1.3 removed RSA
key exchange entirely (using ephemeral ECDH instead), killing this class for the handshake.

### RSA signature verification bugs

Signatures have their own recurring implementation flaws:

- **Bleichenbacher's `e=3` signature forgery** — a verifier that doesn't strictly check PKCS#1 v1.5
  signature padding can be fooled by a forged signature whose cube is *almost* the right structure
  (exploiting the low exponent). It hit Firefox NSS, OpenSSL, and others.
- **"BERserk," `kid`/algorithm confusion** — and, from Notebook 6 Chapter 3, the **JWT RS256→HS256**
  algorithm-confusion attack, which abuses the fact that the RSA *public* key is public: switch the
  JWT to HS256 and HMAC-sign with the public key as the secret.

The through-line: **RSA's malleability and the fragility of v1.5 padding** make *strict, constant-time
verification* essential. Prefer **RSA-PSS** and vetted libraries; never hand-roll RSA padding or
verification.

### The RSA-CRT fault attack (why a single glitch leaks the key)

For speed, RSA decryption/signing usually uses the **Chinese Remainder Theorem (CRT)**: instead of
one big `c^d mod n`, compute two smaller exponentiations mod `p` and mod `q`, then recombine. It's
~4× faster — but it opens a devastating **fault attack** (Boneh–DeMillo–Lipton). If a hardware glitch
(induced by voltage/clock/laser fault injection, or just a cosmic-ray bit flip) corrupts *one* of
the two half-computations during a signature, the resulting faulty signature `s'` reveals a prime:

```
gcd(s'^e - m,  n)  =  p        (one GCD -> factor n -> full private key)
```

A single faulty signature factors the modulus. This is a real, exploited attack against smartcards
and HSMs. **Fixes:** verify the signature *before* releasing it (recompute `s^e mod n == m` and abort
on mismatch), and use fault-resistant hardware. The lesson generalizes: **implementations leak keys
through side channels and faults**, even when the abstract math is perfect — which is why you use
audited libraries and hardware, not homemade RSA.

---

## Part 6: Elliptic-Curve Cryptography (ECC) — More Security, Smaller Keys

**ECC** provides the same capabilities as RSA/DH (encryption, key exchange, signatures) but based on
the **elliptic-curve discrete log problem (ECDLP)**, which is *much harder per bit* — so keys are
dramatically smaller for equal security.

An elliptic curve is the set of points satisfying `y² = x³ + ax + b` (over a finite field). You can
"add" two points geometrically (a defined group operation), and **scalar multiplication** —
`Q = k·G` (adding a base point `G` to itself `k` times) — is the one-way function: computing `Q`
from `k` is fast; recovering `k` from `Q` and `G` (the ECDLP) is infeasible. The **private key** is
the scalar `k`; the **public key** is the point `Q = k·G`.

```mermaid
flowchart LR
    k[private key: scalar k] -->|k * G : EASY| Q[public key: point Q]
    Q -.recover k from Q, G : INFEASIBLE ECDLP.-> k
    G[base point G on curve] --> Q
```

**Why ECC wins on size** (the practical headline):

| Security level | RSA/DH key | ECC key |
|---|---|---|
| 112-bit | 2048-bit | 224-bit |
| 128-bit | 3072-bit | 256-bit |
| 192-bit | 7680-bit | 384-bit |
| 256-bit | 15360-bit | 512-bit |

Smaller keys mean less bandwidth, faster operations, and lower power — decisive for mobile, IoT, and
TLS at scale. The internet has largely **moved from RSA to ECC** for key exchange and signatures.

**Named curves you'll meet:**

| Curve | Use | Notes |
|---|---|---|
| **P-256** (secp256r1) | ECDH/ECDSA, TLS | NIST curve, ubiquitous |
| **P-384 / P-521** | higher security | NIST |
| **Curve25519** | ECDH (X25519) | Bernstein; fast, safe, misuse-resistant |
| **Ed25519** | signatures (EdDSA) | deterministic, fast, no-nonce-reuse pitfall |
| **secp256k1** | Bitcoin/Ethereum keys | the blockchain curve |

**Curve25519/Ed25519 are the modern preferred choices** because they're designed to be
*misuse-resistant* — constant-time, no invalid-curve pitfalls, and (for Ed25519) **deterministic
nonces** that eliminate the reused-nonce catastrophe (Part 9). NIST P-curves are fine but easier to
implement incorrectly.

**How do you actually *encrypt* to an ECC key?** RSA encrypts directly, but ECC keys are for
key-agreement and signatures — you don't "RSA-style encrypt" to a point. The standard is **ECIES**
(Elliptic Curve Integrated Encryption Scheme): the sender makes an *ephemeral* keypair, does ECDH
with the recipient's public key to derive a shared secret, runs it through a **KDF** (Chapter 4) to
get an AES key, and AEAD-encrypts the data — sending the ephemeral public key alongside the
ciphertext. It's hybrid encryption (Chapter 1) built on ECDH, and it's what "encrypt to an ECC
public key" means in practice (used in Bitcoin messaging, `age`, and messaging apps). The mental
model: **ECC never encrypts bulk data; it agrees a key that AES then uses.**

```bash
# Generate an ECC keypair (X25519 for key exchange, Ed25519 for signatures)
openssl genpkey -algorithm X25519 -out x25519_priv.pem
openssl genpkey -algorithm ED25519 -out ed25519_priv.pem
openssl pkey -in ed25519_priv.pem -pubout -out ed25519_pub.pem
```

---

## Part 7: ECC Attacks — Invalid Curves and Bad Parameters

ECC's small keys come with sharp implementation edges. You don't attack the ECDLP; you attack
sloppy point handling and parameters.

- **Invalid-curve attacks.** If a server does ECDH but **doesn't verify the received point is
  actually on the expected curve**, an attacker sends points on a *weaker* curve (with small-order
  subgroups). The shared secret then lives in a tiny group, and the attacker recovers the server's
  private key piece by piece via the Chinese Remainder Theorem. **Fix: always validate that a
  received point is on the correct curve and in the right subgroup.**
- **Small-subgroup / invalid-point attacks** — the DH cousin (Part 8): points not in the prime-order
  subgroup leak private-key bits. X25519 is designed to resist this (it clamps scalars and its group
  structure avoids the pitfall).
- **Weak/backdoored curves.** **Dual_EC_DRBG** was a NIST random-number generator with a suspected
  NSA backdoor via chosen curve constants — a reminder to prefer well-audited curves
  (Curve25519/Ed25519) with *nothing-up-my-sleeve* parameters.
- **Twist attacks** — sending points on the curve's "twist" if the implementation doesn't check;
  again defeated by validation and by curves designed to be twist-secure.

The meta-lesson matches RSA: **the curve math is strong; parameter and point validation is where
implementations bleed.** Use a vetted library, prefer X25519/Ed25519, and never accept an unvalidated
public point.

---

## Part 8: Diffie-Hellman Key Exchange and Forward Secrecy

**Diffie-Hellman (DH)** is the original public-key breakthrough (1976): two parties agree on a
**shared secret over a fully public channel**, such that an eavesdropper who sees everything cannot
compute it. It's the direct answer to the key-distribution problem.

**Classic DH** (over integers mod a prime `p`, with generator `g`):

1. Public parameters: a large prime `p` and generator `g`.
2. Alice picks secret `a`, sends `A = gᵃ mod p`. Bob picks secret `b`, sends `B = gᵇ mod p`.
3. Alice computes `s = Bᵃ mod p`; Bob computes `s = Aᵇ mod p`. Both equal `g^(ab) mod p` — the
   **shared secret**.

An eavesdropper sees `g, p, A, B` but computing `s` requires the discrete log (recovering `a` or
`b`) — infeasible.

```mermaid
sequenceDiagram
    participant A as Alice (secret a)
    participant B as Bob (secret b)
    A->>B: A = g^a mod p
    B->>A: B = g^b mod p
    Note over A: s = B^a = g^(ab)
    Note over B: s = A^b = g^(ab)
    Note over A,B: shared secret s — eavesdropper can't compute it (DLP)
```

A tiny numeric example makes the "shared secret from public values" click:

```python
# TOY Diffie-Hellman (small numbers to see the mechanism)
p, g = 23, 5              # public parameters
a, b = 6, 15             # Alice's & Bob's secrets (never sent)
A = pow(g, a, p)         # 8   Alice -> Bob (public)
B = pow(g, b, p)         # 19  Bob -> Alice (public)
s_alice = pow(B, a, p)   # 19^6 mod 23 = 2
s_bob   = pow(A, b, p)   # 8^15 mod 23 = 2
print(s_alice, s_bob)    # 2 2  -> same shared secret; eavesdropper saw only 23,5,8,19
```

An eavesdropper who saw `p=23, g=5, A=8, B=19` still cannot get `2` without solving the discrete log
(recovering `a=6` or `b=15`). With 2048-bit `p`, that's infeasible.

**ECDH** is the same idea on elliptic curves: Alice sends `a·G`, Bob sends `b·G`, both compute
`ab·G`. Smaller, faster — the modern default (**X25519** specifically).

### Man-in-the-middle — DH needs authentication

Raw DH provides **no authentication**: an active attacker in the middle can run a separate DH with
each side and relay, reading everything. So DH must be **authenticated** — the exchanged public
values are signed (with a certificate/long-term key) or bound via a password (PAKE). This is exactly
what TLS does: ECDH for the key, plus a **signature over the handshake** using the server's
certificate to prove identity.

### Forward secrecy — the killer feature

The decisive reason modern TLS uses **ephemeral** DH/ECDH (DHE/ECDHE): **forward secrecy**. If the
DH keys are *ephemeral* (fresh, random per session, discarded after), then even if the server's
long-term private key is later compromised, **past recorded sessions cannot be decrypted** — the
ephemeral secrets are gone. Contrast **RSA key transport** (old TLS), where the client encrypted the
pre-master secret to the server's long-term RSA key: capture that traffic, steal the key years
later, decrypt everything retroactively. TLS 1.3 **mandates ephemeral (EC)DH** for exactly this
reason.

| Property | RSA key transport (old) | (EC)DHE (modern) |
|---|---|---|
| Forward secrecy | ✗ (key compromise = all past traffic) | ✓ ephemeral keys discarded |
| In TLS 1.3 | removed | mandatory |
| MITM without auth | possible | possible — must authenticate |

---

## Part 9: ECDSA/DSA Nonce Reuse — The Catastrophic Signature Bug

Signatures get their own chapter (Chapter 6), but one asymmetric attack belongs here because it's
pure key-recovery math and one of the most famous real breaks. **DSA and ECDSA signatures use a
random per-signature nonce `k`** — and if `k` is ever **reused** or **predictable**, the **private
key falls out algebraically**.

Each ECDSA signature is a pair `(r, s)` where `s = k⁻¹(hash + r·privkey) mod n`. Sign two different
messages with the *same* `k`, and you get two equations with two unknowns (`k` and `privkey`) —
solvable directly:

```
s1 = k⁻¹(z1 + r·d)      s2 = k⁻¹(z2 + r·d)     (same k -> same r)
k = (z1 − z2) / (s1 − s2)         then      d = (s1·k − z1) / r
-> the private key d is recovered from two signatures.
```

```python
# ECDSA private-key recovery from a reused nonce (schematic)
# given two signatures (r, s1),(r, s2) on hashes z1,z2 with the SAME r (=> same k)
k = (z1 - z2) * pow(s1 - s2, -1, n) % n
d = (s1 * k - z1) * pow(r, -1, n) % n     # <- attacker now holds the private key
```

**Real disasters:** the **Sony PS3** code-signing key was extracted because Sony used a *constant*
`k` for every signature; **Bitcoin wallets** have been drained after Android's broken RNG produced
repeated `k` values. This is the exact analog of Chapter 1's two-time-pad and Chapter 2's nonce
reuse — *reuse the random value, lose the secret.*

**The fix:** never reuse or predict `k` — generate it from a CSPRNG, or better, use **deterministic
nonces** (RFC 6979) which derive `k` deterministically from the key and message (so it's unique per
message with no RNG dependency), or use **Ed25519**, which is deterministic by design and immune to
this entire class. When you see custom ECDSA signing, check the nonce first.

---

## Part 10: Hands-On Lab — RSA End to End, Hybrid, and a Nonce-Reuse Break

Three exercises: build/inspect RSA, do hybrid encryption the right way, and recover an ECDSA key
from reused nonces. Local and safe.

### Tool from scratch: OpenSSL pkeyutl and Python `cryptography`

You've met OpenSSL (`genrsa`, `genpkey`, `pkeyutl`, `pkey`). For programmatic work, Python's
**`cryptography`** library provides safe, high-level RSA/ECC/DH with correct padding by default.

### 10.1 RSA keygen, encrypt, sign — and see raw vs OAEP

```bash
# Keypair
openssl genrsa -out priv.pem 2048 && openssl rsa -in priv.pem -pubout -out pub.pem

# Correct: OAEP encryption (randomized — encrypt the same file twice, different ciphertext)
echo "the launch code is 1234" > m.txt
openssl pkeyutl -encrypt -pubin -inkey pub.pem -pkeyopt rsa_padding_mode:oaep -in m.txt -out c1.bin
openssl pkeyutl -encrypt -pubin -inkey pub.pem -pkeyopt rsa_padding_mode:oaep -in m.txt -out c2.bin
cmp c1.bin c2.bin && echo "same" || echo "different"   # -> different (OAEP randomizes)

# Decrypt
openssl pkeyutl -decrypt -inkey priv.pem -pkeyopt rsa_padding_mode:oaep -in c1.bin
# -> the launch code is 1234
```

Repeat with `rsa_padding_mode:none` (raw) and you'll get **identical** ciphertext both times — the
deterministic leak that makes textbook RSA unusable, seen directly.

### 10.2 Hybrid encryption (how real systems use RSA)

```python
# RSA-OAEP wraps a random AES key; AES-GCM encrypts the data (the standard pattern)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()

data = b"a large secret document " * 1000        # too big for RSA directly
aes_key = AESGCM.generate_key(256)               # random symmetric key
nonce = os.urandom(12)
ct = AESGCM(aes_key).encrypt(nonce, data, None)  # fast bulk encryption

# Wrap the AES key with RSA-OAEP (the ONLY thing RSA encrypts)
wrapped = pub.encrypt(aes_key, padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Recipient: unwrap the key with the private key, then decrypt the data
unwrapped = priv.decrypt(wrapped, padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
pt = AESGCM(unwrapped).decrypt(nonce, ct, None)
print(pt == data)     # True
```

This is precisely how PGP, TLS (pre-1.3), and encrypted messaging move data: **RSA/ECDH for the
little key, AES for the bytes.** Notice RSA never touches the bulk data.

### 10.3 Recover an ECDSA private key from reused nonces

```python
# Simulate a signer that reuses k (the bug), then recover the private key.
from ecdsa import SigningKey, NIST256p, util
import hashlib
n = NIST256p.order
sk = SigningKey.generate(curve=NIST256p)
d_real = sk.privkey.secret_multiplier

k = 0x12345                                   # BUG: fixed nonce for both signatures
def sign(msg):
    z = int(hashlib.sha256(msg).hexdigest(), 16)
    r = (k * NIST256p.generator).x() % n
    s = (pow(k, -1, n) * (z + r * d_real)) % n
    return r, s, z

r1, s1, z1 = sign(b"transfer 10")
r2, s2, z2 = sign(b"transfer 9999")           # same k -> same r

# Attack: k and d recovered from the two signatures
k_rec = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
d_rec = ((s1 * k_rec - z1) * pow(r1, -1, n)) % n
print("recovered == real:", d_rec == d_real)  # True — full key compromise
```

Output `recovered == real: True` — two signatures with a repeated nonce hand you the private key,
no curve-breaking required. **The fix:** RFC 6979 deterministic nonces or Ed25519. You've now seen
the exact mechanism behind the PS3 and Bitcoin key thefts.

---

## Part 11: Post-Quantum, and Detection & Defense Angle

### The quantum threat and PQC

**Shor's algorithm** on a large fault-tolerant quantum computer would break RSA, DH, and ECC by
solving factoring and discrete logs efficiently. That hasn't happened, but **"harvest now, decrypt
later"** is a real threat: adversaries record encrypted traffic today to decrypt once quantum
computers arrive. NIST has standardized **post-quantum algorithms** — **ML-KEM (Kyber)** for key
exchange and **ML-DSA (Dilithium)** / SLH-DSA for signatures — based on lattice/hash problems Shor
doesn't break. Deployment is beginning as **hybrid** schemes (classical ECDH **+** ML-KEM together,
so you're safe if either holds). Symmetric crypto and hashes need only bigger parameters (AES-256,
SHA-384). If you're designing for long-lived secrets, plan for PQC now.

### Defensive guidance

```mermaid
flowchart TD
    A[Using asymmetric crypto] --> B{Purpose?}
    B -->|Encrypt to someone| C[RSA-OAEP or ECIES — never raw/v1.5]
    B -->|Agree a key| D[ECDHE / X25519 — ephemeral = forward secrecy]
    B -->|Sign| E[Ed25519 or RSA-PSS — deterministic/strict verify]
    C --> F[hybrid: wrap an AES key, AES-GCM the data]
    D --> G[authenticate the exchange — else MITM]
```

**Do:**

- **Encryption:** RSA-**OAEP** or ECIES; always **hybrid** (wrap an AES key). Never raw/textbook RSA
  or PKCS#1 v1.5 encryption.
- **Key exchange:** **ephemeral** ECDHE / **X25519** for forward secrecy; **authenticate** it (cert
  or signature) to stop MITM.
- **Signatures:** **Ed25519** (deterministic, misuse-resistant) or **RSA-PSS**; strict, constant-time
  verification; never reuse/predict the ECDSA nonce.
- **Key sizes:** RSA ≥ 2048 (3072+ for long-term); ECC 256+ (Chapter 1's table). Retire RSA-1024.
- **Validate parameters:** verify received EC points are on the correct curve/subgroup; prefer
  curves with nothing-up-my-sleeve constants (Curve25519); avoid Dual_EC_DRBG.
- **Protect private keys:** HSM/KMS, never in repos; strong entropy for keygen (a weak RNG makes keys
  factorable — the 2012 "**Mining your Ps and Qs**" study found thousands of RSA keys sharing primes
  due to bad embedded RNGs, factorable by a simple GCD).

**Detection / red flags (grep + behavior):** raw/textbook RSA (`padding_mode:none`,
`Cipher.getInstance("RSA/ECB/NoPadding")`), **PKCS1v15** *encryption* (Bleichenbacher), RSA keys < 2048,
`e=3` with unpadded/short messages, distinguishable padding errors/timing on RSA decrypt, custom
ECDSA signing (nonce reuse), unvalidated EC points, shared/duplicate RSA moduli across keys (weak
RNG — test with a batch GCD), and hardcoded private keys.

---

## Part 12: Key Formats and Real-World Composition — TLS 1.3, SSH, PGP

Two practical topics that turn this theory into things you'll actually touch.

### Key and certificate formats (so you can read what's on disk)

Asymmetric keys travel in a handful of encodings; recognizing them saves hours:

| Format | What it is | Looks like |
|---|---|---|
| **PEM** | Base64 of DER, with header lines | `-----BEGIN PRIVATE KEY-----` |
| **DER** | binary ASN.1 encoding | raw bytes (not text) |
| **PKCS#1** | RSA-specific key structure | `-----BEGIN RSA PRIVATE KEY-----` |
| **PKCS#8** | generic private-key wrapper (any algo) | `-----BEGIN PRIVATE KEY-----` |
| **SPKI** | generic public-key wrapper | `-----BEGIN PUBLIC KEY-----` |
| **OpenSSH** | SSH key format | `ssh-ed25519 AAAA...` / `-----BEGIN OPENSSH PRIVATE KEY-----` |
| **PKCS#12 / PFX** | bundle of key + cert chain, password-protected | `.p12`/`.pfx` binary |

```bash
openssl pkey -in priv.pem -text -noout        # inspect any private key
openssl rsa  -in rsa.pem -text -noout          # RSA specifics (n, e, d, primes)
ssh-keygen -t ed25519 -f id_ed25519            # generate an SSH Ed25519 keypair
openssl pkcs12 -in bundle.pfx -nodes           # unpack a PFX (key + chain)
```

**Security note:** a private key found in a repo, a `.pfx` with a weak password, or an SSH key
without a passphrase is a critical finding — the whole point of the private key is that it never
leaves your control. `gitleaks`/`trufflehog` scan for `BEGIN ... PRIVATE KEY` blocks precisely
because leaked keys are so common and so damaging.

### How TLS 1.3 composes everything in this notebook

A single HTTPS handshake uses *every* primitive so far — a perfect capstone:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: ClientHello + ephemeral ECDH public (X25519)
    S->>C: ServerHello + ephemeral ECDH public
    Note over C,S: both derive shared secret via ECDH (Part 8)
    S->>C: Certificate (server's public key) + signature over the transcript
    Note over C: verify cert chain (PKI, Ch 6) + verify signature (Ed25519/RSA-PSS)
    Note over C,S: HKDF derives AES/ChaCha keys from the ECDH secret
    C->>S: Finished (now AES-256-GCM / ChaCha20-Poly1305, Ch 2)
```

- **Ephemeral ECDH (X25519)** agrees a shared secret → **forward secrecy** (Part 8).
- The server's **certificate + signature** authenticate the exchange (stops MITM; PKI is Chapter 6).
- **HKDF** (a hash-based KDF, Chapter 4) stretches the ECDH secret into symmetric keys.
- **AES-GCM / ChaCha20-Poly1305** (Chapter 2) encrypt the actual data.

That single flow is *why* this notebook is ordered as it is: TLS is symmetric + asymmetric + hashing
+ PKI, each doing the job only it can. When you audit TLS, you're auditing all of it at once.

### SSH and PGP in one line each

- **SSH** uses ephemeral (EC)DH for the session key and your **Ed25519/RSA** key pair to authenticate
  you to the server (your public key sits in `authorized_keys`; you prove possession of the private
  key). Same hybrid + signature pattern.
- **PGP/GPG** encrypts email/files by wrapping a random symmetric key with the recipient's RSA/ECC
  public key (hybrid), and signs with your private key for authenticity/non-repudiation — the exact
  composition from Part 10's lab, productized.

---

## Part 13: Final Revision / Summary

- **Asymmetric crypto solves key distribution** with a **key pair**: public key (encrypt/verify) is
  published; private key (decrypt/sign) is secret; you can't derive private from public. It's slow,
  so it's used in **hybrid** mode — protect a small AES key, let AES do the bulk.
- **It rests on trapdoor one-way math:** **factoring** (RSA), **discrete log** (DH/DSA), **ECDLP**
  (ECC). ECDLP is hardest per bit → **256-bit ECC ≈ 3072-bit RSA**. All three fall to **Shor's**
  quantum algorithm → post-quantum crypto (ML-KEM/ML-DSA).
- **RSA:** `n=pq`, public `(n,e=65537)`, private `d=e⁻¹ mod φ(n)`; `c=mᵉ mod n`, `m=cᵈ mod n`.
  **Textbook RSA is broken** (deterministic, malleable, small-`e` cube-root, common-modulus,
  Håstad). Use **OAEP** for encryption, **PSS** for signatures. **PKCS#1 v1.5 → Bleichenbacher**
  padding-oracle key/secret recovery.
- **ECC** gives equal security with tiny keys via ECDLP; prefer **X25519** (ECDH) and **Ed25519**
  (signatures) for misuse resistance. Attacks target **invalid/unvalidated points**, weak/backdoored
  curves (Dual_EC_DRBG), not the math.
- **Diffie-Hellman / ECDH** agree a shared secret over a public channel (DLP/ECDLP protects it) but
  provide **no authentication** — must be authenticated (else MITM). **Ephemeral (EC)DHE gives
  forward secrecy**; TLS 1.3 mandates it and dropped RSA key transport.
- **ECDSA/DSA nonce reuse or predictability = private-key recovery** from two signatures (PS3,
  Bitcoin). Fix: RFC 6979 deterministic nonces or Ed25519.
- **Direction discipline:** encrypt with the *recipient's public* key; sign with *your private* key.
  ECC doesn't encrypt directly — **ECIES** (ECDH + KDF + AEAD) does the "encrypt to a curve key" job.
- **RSA parameters are a minefield** (Wiener's small-`d`, Fermat's close primes, Coppersmith partial
  leaks, RSA-CRT fault, shared-prime weak-RNG keys) — *never* generate or implement RSA yourself.
- **Real-world composition:** TLS 1.3 = ephemeral ECDH (forward secrecy) + certificate signature
  (auth) + HKDF (key derivation) + AES-GCM/ChaCha20-Poly1305 (bulk). SSH and PGP use the same hybrid
  pattern. Key formats: PEM/DER, PKCS#1/#8, SPKI, OpenSSH, PKCS#12 — a leaked `BEGIN PRIVATE KEY` is
  critical.
- **The pattern (again):** the math is strong; **padding, key size, randomness, and parameter
  validation** are where asymmetric crypto breaks.

---

## Part 14: Cheat Sheet / Quick Reference

**Pick the primitive**

```
Encrypt to someone:  RSA-OAEP or ECIES  (+ hybrid: wrap an AES key)   NEVER raw/v1.5
Agree a key:         X25519 / ECDHE (ephemeral -> forward secrecy) + authenticate
Sign:                Ed25519  or  RSA-PSS    (strict, constant-time verify)
Key sizes:           RSA >= 2048 (3072 long-term); ECC 256+; retire RSA-1024
```

**RSA in one box**

```
n = p*q ; e = 65537 ; d = e^-1 mod (p-1)(q-1)
encrypt c = m^e mod n ;  decrypt m = c^d mod n   (sign = swap e/d)
```

**Equivalent strength:** 256-bit ECC ≈ 3072-bit RSA ≈ AES-128 (128-bit level).

**Direction:** encrypt → recipient's **public** key · sign → your **private** key. ECC "encrypt" =
**ECIES** (ephemeral ECDH + KDF + AEAD).

**Key formats on disk**

```
-----BEGIN PRIVATE KEY-----      PKCS#8 (any algo)     |  ssh-ed25519 AAAA...  OpenSSH pub
-----BEGIN RSA PRIVATE KEY-----  PKCS#1 (RSA)          |  .p12/.pfx            PKCS#12 bundle
-----BEGIN PUBLIC KEY-----       SPKI (any algo)       |  (leaked key = critical finding)
```

**Attack → cause → fix**

| Attack | Cause | Fix |
|---|---|---|
| Small-e cube root / Håstad | textbook RSA, e=3, short msg | OAEP padding |
| Wiener | small private exponent d | d > n^0.25; let library pick |
| Coppersmith / partial key | leaked bits of p or plaintext | full-entropy keygen; padding |
| Fermat factorization | p, q too close | independent random primes |
| RSA-CRT fault | glitch during CRT signing | verify signature before release |
| Common modulus | shared n | unique n per key |
| Bleichenbacher / ROBOT | PKCS#1 v1.5 padding oracle | OAEP; indistinguishable errors; TLS1.3 |
| Signature forgery (e=3) | lax v1.5 verify | PSS; strict verify |
| Invalid-curve | unvalidated EC point | validate on-curve/subgroup; X25519 |
| ECDSA nonce reuse | repeated/predictable k | RFC 6979 / Ed25519 |
| Harvest-now-decrypt-later | quantum future | hybrid PQC (ML-KEM) |
| Shared RSA primes | weak keygen RNG | strong CSPRNG; batch-GCD audit |

**OpenSSL**

```bash
openssl genrsa -out p.pem 2048 ; openssl rsa -in p.pem -pubout -out pub.pem
openssl genpkey -algorithm X25519 -out x.pem ; openssl genpkey -algorithm ED25519 -out e.pem
openssl pkeyutl -encrypt -pubin -inkey pub.pem -pkeyopt rsa_padding_mode:oaep -in m -out c
```

---

## Part 15: Common Pitfalls

- **Textbook/raw RSA.** Deterministic + malleable + cube-root + common-modulus. Use OAEP (encrypt)
  and PSS (sign).
- **PKCS#1 v1.5 encryption.** Bleichenbacher padding oracle → secret recovery. Migrate to OAEP.
- **Encrypting bulk data directly with RSA.** Too slow / size-limited. Hybrid: wrap an AES key.
- **RSA keys < 2048 bits or `e=3` unpadded.** Factorable / cube-root-able. Use 2048+ and e=65537
  with OAEP/PSS.
- **Unauthenticated Diffie-Hellman.** MITM reads everything. Authenticate the exchange (cert/PAKE).
- **Static (non-ephemeral) key exchange.** No forward secrecy — key theft decrypts all past traffic.
  Use ECDHE/X25519.
- **Reusing/predicting the ECDSA nonce `k`.** Two signatures → private key (PS3, Bitcoin). RFC 6979
  or Ed25519.
- **Not validating received EC points.** Invalid-curve/twist attack recovers the private key.
  Validate on-curve and in-subgroup (or use X25519, which is designed around this).
- **Trusting sketchy curves / RNGs (Dual_EC_DRBG, weak embedded RNG).** Shared/factorable keys.
  Vetted curves + strong CSPRNG.
- **Choosing your own RSA parameters** (small `d`, close primes, custom `e`). Wiener/Fermat/
  Coppersmith. Let a vetted library generate keys.
- **RSA-CRT without verify-before-release.** A single fault factors `n`. Verify the signature first.
- **"Encrypting" to an ECC key like RSA.** ECC agrees keys / signs; use **ECIES** (ECDH + KDF + AEAD).
- **Confusing sign/encrypt direction.** Encrypt with the *recipient's public* key; sign with *your
  private* key.
- **Hardcoded/leaked private keys.** Game over. HSM/KMS; never in repos.
- **Ignoring the quantum horizon for long-lived secrets.** Harvest-now-decrypt-later. Plan hybrid PQC
  (ML-KEM + classical ECDH).
- **Shipping a private key in a container image, `.pfx`, or repo.** Scanners (gitleaks/trufflehog)
  find `BEGIN ... PRIVATE KEY` instantly; so do attackers. Keys live in HSM/KMS only.

---

## Part 16: Practice Labs & Resources

- **CryptoHack — RSA, Diffie-Hellman, and Elliptic Curves** sections are the definitive practice:
  textbook-RSA attacks (small-e, Håstad, common modulus), padding, DH parameter attacks, and ECDLP/
  point-validation challenges. Free and graded.
- **Cryptopals — Set 5 & 6** implement DH and MITM, RSA (including **e=3 broadcast** and a
  **Bleichenbacher padding oracle**), and DSA nonce recovery — the canonical hands-on path for this
  chapter's attacks.
- **picoCTF / CTF crypto categories** regularly feature RSA (weak keys, `factordb`, common modulus)
  and ECDSA nonce-reuse challenges; **RsaCtfTool** automates many textbook-RSA breaks (Wiener,
  Håstad, small-`e`, Fermat, factordb lookup) — run it against a deliberately weak key you generate.
- **CryptoHack — "No Random, No Bias" / ECDSA** challenges walk the nonce-reuse and biased-nonce
  key-recovery attacks end to end.
- **"Mining your Ps and Qs" (Heninger et al.)** — read it; then use a batch-GCD script on a set of
  real RSA public keys to find shared primes from weak RNGs.
- **testssl.sh / a TLS lab** — inspect whether a server offers forward-secret (EC)DHE suites vs
  legacy RSA key transport, connecting Part 8 to real config.
- **Tooling to master:** OpenSSL (`genrsa`/`genpkey`/`pkeyutl`), Python **`cryptography`** and
  `pycryptodome`, `sympy`/`gmpy2` for the math, **RsaCtfTool**, `factordb`, and the `ecdsa` library
  for nonce-reuse demos.

**Practice questions / mini-labs to self-test:**

1. Generate a 2048-bit RSA key, encrypt the same short message twice with raw RSA and twice with
   OAEP; show which produces identical ciphertext and explain the security consequence.
2. Given two RSA ciphertexts of the *same* message under `e=3` and three different moduli, describe
   how to recover the plaintext, and name the attack.
3. Explain, with the ECDSA equations, why two signatures sharing a nonce reveal the private key, and
   state two independent fixes.
4. Why does TLS 1.3 mandate ephemeral (EC)DH and remove RSA key transport? Define forward secrecy in
   your answer.
5. A service does ECDH but never checks that the client's point is on the curve. Name the attack,
   what it recovers, and the fix.
6. You capture two RSA public keys from different devices and find `gcd(n1, n2) > 1`. What does that
   reveal, why did it happen, and what does it let you compute?
7. Walk the TLS 1.3 handshake and label which chapter's primitive provides forward secrecy,
   authentication, key derivation, and bulk confidentiality.
8. A firmware team sets a small RSA private exponent `d` "for speed on the microcontroller." Name the
   attack this enables and the mathematical tool that performs it.

If you can name the right primitive for encrypt/agree/sign, size keys across families, and spot
textbook RSA, a reused ECDSA nonce, an unauthenticated DH, or a leaked private key on sight, you
own this chapter.
