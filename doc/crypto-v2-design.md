# geheimnis v2 — convergent portable cryptography

Status: **DESIGN / for review** (no code yet). Supersedes the v1 primitives.

A single, portable (JVM + browser + Node), modern crypto layer that backs
**both** konserve/datahike value encryption **and** the kabel auth / P2P
identity layer. One primitive suite, one interface, native on each platform.

---

## 1. Why replace v1

v1 (`geheimnis.aes` / `.rsa` / `.md5`) is 2016 hobby-grade and unsafe to build a
trust boundary on:

- **AES-256-CBC, unauthenticated**, with a *static hardcoded default IV* and a
  single-SHA-512 "KDF" (no salt/work-factor at that layer). No AEAD tag → tamper
  is undetectable; PKCS7 error path is padding-oracle-shaped.
- **RSA is raw textbook** modPow — no PKCS#1/OAEP padding, **no sign/verify at
  all**. Malleable, deterministic; unusable.
- **MD5 namespaces are 0-byte** (advertised in the README, don't compile).
- CLJS path is `goog.crypt` (AES) + `jsbn` (RSA), fully synchronous.
- Randomness: JVM `SecureRandom` (ok); **CLJS at-rest entropy is `Math.random`**
  (konserve salt = `hasch/random-uuid`) — not a CSPRNG.

Mitigating facts:
- **konserve is the only consumer** and it papers over the static-IV flaw (random
  per-blob salt → derived IV+key) — but still **CBC, no MAC**.
- **simmis encrypts nothing at rest today** (all stores `null-encryptor`). So the
  storage side is **greenfield** — no ciphertext migration, forward-only.
- The **live** auth crypto is `kabel.auth.jwt` on `java.security` (HS256/RS256,
  alg-pinned) — the modern part; we extend it, not replace it.

---

## 2. Goals / non-goals

**Goals**
- One `.cljc` façade, identical API on JVM / browser / Node.
- Authenticated encryption (AEAD) for konserve/datahike at-rest and in-transit.
- Modern signatures (peer identity) + key agreement (P2P channels).
- Native primitives where possible (zero JS crypto bytes shipped); a minimal
  audited fallback only for the one gap (curves on old browsers).
- A clean bridge from "JWT verify today" to "peer Ed25519 signatures" on one
  keypair.

**Non-goals**
- Not a general OpenSSL-compatible cipher zoo. One opinionated suite.
- Not changing hasch: hasch stays the structural content hash for addressing/
  dedup. It is **not** a MAC and is **not** touched here — `random-uuid` is fine
  for addressing (needs uniqueness, not unpredictability); only *crypto* material
  moves to the CSPRNG.

---

## 3. Primitive suite (name-locked)

| purpose | primitive | JVM | CLJS/Node |
|---|---|---|---|
| AEAD (at-rest / in-transit) | **AES-256-GCM** (96-bit nonce) | `javax.crypto` GCM | Web Crypto `AES-GCM` |
| signatures (identity) | **Ed25519** | `java.security` EdDSA (JDK15+) | Web Crypto Ed25519, **tweetnacl fallback** (old browsers) |
| key agreement (channels) | **X25519** → HKDF → GCM key | `java.security` XDH (JDK11+) | Web Crypto X25519, tweetnacl fallback |
| KDF | **HKDF-SHA-256** | HMAC-HKDF (native HMAC) | Web Crypto HKDF |
| hash / MAC | **SHA-256**, **HMAC-SHA-256** | native | Web Crypto |
| password KDF (server only) | **Argon2id** (bcrypt kept for legacy hashes) | BC/argon2 lib | n/a |
| CSPRNG | random-bytes | `SecureRandom` | `crypto.getRandomValues` |

AES-256-GCM is chosen over ChaCha20-Poly1305 because it is the **only AEAD native
on both** the JVM and Web Crypto (no bundled cipher). Ed25519/X25519 over
ECDSA-P256/RSA for speed, small keys (32 B), determinism, misuse-resistance.

---

## 4. Namespace layout (add new, deprecate old)

New (`org.replikativ.geheimnis.*`):

```
org.replikativ.geheimnis.core     ; the façade protocol + platform dispatch, random-bytes
org.replikativ.geheimnis.aead     ; aead-encrypt / aead-decrypt (AES-256-GCM), envelope
org.replikativ.geheimnis.sign     ; ed25519 gen-keypair / sign / verify
org.replikativ.geheimnis.dh       ; x25519 gen-keypair / agree ; hkdf
org.replikativ.geheimnis.hash     ; sha-256 / hmac-sha-256 / ct-equal?
org.replikativ.geheimnis.codec    ; base64url, byte<->hex, key (de)serialization
```

Deprecated (kept for read-back compatibility, marked `^:deprecated`, never the
default, no new features):

```
geheimnis.aes / org.replikativ.geheimnis.aes   ; CBC decrypt only (read legacy blobs)
geheimnis.rsa / …rsa                           ; DELETE (raw RSA — unsafe, unused)
geheimnis.md5 / …md5                           ; DELETE (empty)
```

`geheimnis.base64` folds into `…codec` (a v1 alias stays for compat).

---

## 5. The portable interface (async-shaped)

Web Crypto is Promise-based; JVM crypto is synchronous. To keep ONE cross-platform
signature, **every façade op returns a `core.async` channel** yielding the result
(or an error value). JVM impls resolve synchronously into the channel; CLJS impls
bridge the Web Crypto Promise onto the channel. konserve and kabel are already
`core.async`/`superv.async`-shaped (`<?-`, `async+sync`), so callers thread it
naturally.

```clojure
;; all return a channel; error surfaces as an ex-info on the channel
(random-bytes n)                       ; -> chan<bytes>   (CSPRNG)
(hash bytes)                           ; -> chan<bytes>   SHA-256
(hmac key bytes)                       ; -> chan<bytes>   HMAC-SHA-256
(ct-equal? a b)                        ; -> bool          constant-time (sync ok)
(hkdf ikm salt info len)               ; -> chan<bytes>

(aead-encrypt key nonce aad plaintext) ; -> chan<bytes>   ct||tag (GCM)
(aead-decrypt key nonce aad ct)        ; -> chan<bytes|⊥>  verifies tag, ⊥ on fail

(sign-gen-keypair)                     ; -> chan<{:public bytes :private key}>
(sign priv msg)                        ; -> chan<bytes>   Ed25519 (64 B)
(verify pub msg sig)                   ; -> chan<bool>

(dh-gen-keypair)                       ; -> chan<{:public bytes :private key}>
(dh-agree my-priv their-pub)           ; -> chan<bytes>   X25519 shared secret
```

A thin `(<sync ...)` helper on the JVM (blocking take) is fine; **CLJS never
blocks** — always channel/`go`.

**Backend dispatch** (`core`): `#?(:clj java.security … :cljs webcrypto-or-shim)`.
On CLJS, feature-detect `js/crypto.subtle` capabilities at load; use Web Crypto
for AEAD/hash/hkdf/dh always, and for Ed25519/X25519 use Web Crypto if present
else the vendored tweetnacl fallback. Fail LOUD (throw) if no CSPRNG — never
silently degrade to `Math.random`.

---

## 6. Envelope formats

**AEAD blob (konserve value):**
```
[ magic(1)=0xA1 | version(1) | key-id(2) | nonce(12) | ciphertext+tag ]
```
- `version`/`key-id` enable algorithm + key rotation (v1 CBC had salt but no
  key-id → could not rotate).
- `nonce` is 12 random bytes from the CSPRNG (mutable cells) — see §7 for the
  immutable-blob deterministic-nonce option.
- konserve's existing header `encryptor-id` byte selects this decryptor; the
  envelope above lives in the value bytes.

**Signature (detached):** raw 64-byte Ed25519 over the message; public key is the
32-byte identity. A JWT `EdDSA` alg reuses the standard JWS layout.

**Key serialization (`codec`):** raw 32-byte public keys, base64url in transport
(JWK `OKP`/`crv:Ed25519` for JWKS/registry interop). Private keys stay
platform-native handles (never serialized off-host by default).

---

## 7. konserve / datahike integration

New encryptor, **id 2 `:aes-gcm`** (alongside `0 null`, `1 aes-cbc` read-only):

- `AEADEncryptor` implements the `PStoreSerializer` encrypt/decrypt hooks, now on
  the **async** façade (the encryptor protocol goes channel-returning; konserve's
  `impl/defaults` path is already `async+sync`).
- **Key derivation:** master `user-key` → `HKDF(user-key, salt, info)` per blob —
  replaces the ad-hoc `SHA-512("key",…)`/`SHA-512("initial-value",…)`. Salt/nonce
  from the CSPRNG (fixes the `Math.random` gap at the source).
- **AAD binds context:** `aad = store-key ‖ version` so a ciphertext can't be
  moved to another key/version and still verify.
- **Immutable content-addressed blobs** (datahike index nodes): the store key is
  already `hash(plaintext)`, so integrity is *also* checkable by recomputing the
  hasch digest on read. Two options: (a) derive a **deterministic nonce =
  HKDF(key, content-hash)[0:12]** so identical values still dedup, or (b) accept
  no-dedup with a random nonce. Recommend (a) for datahike (dedup matters).
- **Mutable head/root cells** (`:db` pointer, store-id): **random nonce per
  write**, and put a monotonically increasing **version counter in the AAD** to
  detect rollback.
- **Migration:** forward-only. New deployments set `:encryptor {:type :aes-gcm
  :key …}`. `id 1` (CBC) stays a **read-only** decryptor for any legacy blobs in
  the wider ecosystem; never shipped as a default. simmis has zero at-rest
  ciphertext today, so nothing to convert.

---

## 8. kabel.auth JWT → P2P bridge

`kabel.auth.jwt` already pins `alg` from trusted config (`verify-signature!`,
`resolve-issuer-key`). Add **`EdDSA` (Ed25519)** as an issuer alg via the façade
`verify`. Then:

- A trusted-issuer registry entry can present an **Ed25519 public key** instead of
  an RSA PEM (JWKS `OKP` keys).
- A peer's **Ed25519 identity keypair** both (a) signs self-issued peer-JWTs and
  (b) anchors **X25519** channel agreement — one keypair for identity + confidential
  channel. This is the seam from "server-issued JWT verified today" to
  "issuer-less peer signatures" without a second identity system.
- The client verify path (browser) uses the same façade — so **CLJS peers verify
  properly**, the original ask, portably (browser + node).

---

## 9. What to retire

- **Raw RSA** (`…rsa`) — delete. If RSA-KEM is ever needed, RSA-OAEP via native.
- **MD5** — delete (empty) and drop from README.
- **Unauthenticated AES-CBC as a write path** — deprecate; keep decrypt-only.
- **Static default IV** and the **single-SHA-512 KDF** — gone (HKDF + CSPRNG).
- **goog.crypt / jsbn** on CLJS — retire; Web Crypto covers the bulk at zero
  bundle cost. Keep at most a single documented goog.crypt SHA-256 *sync* shim
  ONLY if a proven synchronous CLJS hash call-site appears (none found).

---

## 10. Testing

- **Known-answer tests** per primitive (RFC/NIST vectors: AES-GCM, HKDF-SHA256,
  Ed25519 RFC 8032, X25519 RFC 7748).
- **Cross-platform round-trips**: encrypt/sign on JVM → decrypt/verify on CLJS
  (Node + browser via shadow karma) and vice versa, asserting byte-for-byte
  agreement — the interop v1 only hand-checked in comments.
- **konserve integration**: AEAD encryptor round-trip + a **tamper test** (flip a
  ciphertext byte → decrypt must reject), which v1 CBC cannot pass.
- **Negative/security**: wrong-key reject, AAD-mismatch reject, nonce-reuse guard,
  CSPRNG-present assertion.

---

## 11. Open questions

1. Vendored curve fallback: `@noble/curves` (audited, tiny, tree-shakeable) vs
   `tweetnacl-js` (one blob, sync, self-seeds CSPRNG). Lean `@noble/curves`
   (smaller, modern) unless the whole-NaCl-set is wanted later.
2. Deterministic vs random nonce for immutable blobs — recommend deterministic
   (dedup) but confirm datahike relies on value-dedup at the konserve layer.
3. Do we want private-key *export* (encrypted, for backup/recovery), or strictly
   non-exportable keys? Affects Web Crypto `extractable` flag + geheimnis API.
4. Argon2id server dep: Bouncy Castle vs a dedicated argon2 lib; and whether to
   migrate existing bcrypt hashes lazily on next login.

---

## 12. Sequence

1. ✅ constant-time JWT HMAC compare (`kabel.auth.jwt`, done).
2. `geheimnis.core` + `hash` + `codec` + `random-bytes` (CSPRNG both platforms) —
   the smallest useful slice; unblocks CLJS HS256 verify.
3. `aead` (AES-256-GCM) + envelope; konserve `:aes-gcm` encryptor id 2 + tamper
   test.
4. `sign` (Ed25519) + `dh` (X25519) + hkdf; `EdDSA` alg in `kabel.auth.jwt`.
5. Deprecate/delete v1 nses; update konserve require to the consolidated ns.
