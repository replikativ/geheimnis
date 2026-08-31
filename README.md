# geheimnis

[![Clojars Project](https://img.shields.io/clojars/v/org.replikativ/geheimnis.svg)](https://clojars.org/org.replikativ/geheimnis)
[![cljdoc badge](https://cljdoc.org/badge/org.replikativ/geheimnis)](https://cljdoc.org/d/org.replikativ/geheimnis/CURRENT)

Portable cryptography for Clojure **and** ClojureScript (browser + Node) — one
API, native on each platform.

---

> ## ⚠️ Security status — read this first
>
> **v1 (`geheimnis.aes`, `geheimnis.rsa`, `geheimnis.md5`) is deprecated and NOT
> safe for new use.** It provides unauthenticated AES-CBC (no integrity — a
> tampered ciphertext is undetectable), *textbook* RSA (no padding — malleable,
> unsafe), and an empty MD5. Do not use these for anything security-sensitive.
>
> **v2 (`org.replikativ.geheimnis.*`) is a ground-up modern rewrite in progress**
> — authenticated encryption (AES-256-GCM), Ed25519 signatures, X25519 key
> agreement, HMAC/HKDF, a CSPRNG-only randomness source, portable across JVM /
> browser / Node. Status below.

---

## v2 status

The v2 primitives — synchronous foundation, AES-256-GCM (AEAD), Ed25519
signatures, and X25519 key agreement — are landed and verified on JVM and Node
against NIST/RFC vectors and JVM↔Node interop KATs. The Noise transport is a
pre-release implementation and should receive independent security review
before production use.

| namespace | provides | sync? | status |
|---|---|---|---|
| `…geheimnis.core`  | `random-bytes` (CSPRNG), `ct-equal?` | sync | ✅ |
| `…geheimnis.codec` | base64url / hex / utf8, byte-array utils | sync | ✅ |
| `…geheimnis.hash`  | `hmac-sha256`, `hkdf`; `sha256`/`sha512` (via hasch) | sync | ✅ |
| `…geheimnis.aead`  | AES-256-GCM authenticated encryption | async | ✅ |
| `…geheimnis.sign`  | Ed25519 sign / verify | async | ✅ |
| `…geheimnis.dh`    | X25519 key agreement | async | ✅ |
| `…geheimnis.noise` | `Noise_XX_25519_AESGCM_SHA256` handshake and transport | async | 🧪 |

**Design principle — sync where possible, async only where forced.** Hashing,
HMAC and HKDF are synchronous on both platforms (`goog.crypt` / `java.security`),
so token verification (HS256) needs no async. Only AEAD and the elliptic curves
use the async tier (Web Crypto on CLJS, `java.security` on the JVM), returning
`core.async` channels.

**Randomness is CSPRNG-only** — `SecureRandom` on the JVM,
`crypto.getRandomValues` in the browser/Node; it throws loudly rather than fall
back to `Math.random`.

Raw SHA digests live in [hasch](https://github.com/replikativ/hasch) (the
content-hashing library) and are re-exported here — geheimnis owns the *keyed* /
secret crypto, hasch owns unkeyed content hashing.

## Usage

```clojure
;; deps.edn
org.replikativ/geheimnis {:mvn/version "…"}
```

```clojure
(require '[org.replikativ.geheimnis.core :as g]
         '[org.replikativ.geheimnis.hash :as h]
         '[org.replikativ.geheimnis.codec :as codec])

(g/random-bytes 32)                 ; 32 CSPRNG bytes
(h/hmac-sha256 key msg)             ; HMAC-SHA-256
(h/hkdf ikm salt info 32)           ; derive 32 bytes (RFC 5869)
(codec/bytes->b64url some-bytes)    ; unpadded base64url
```

A byte value is a JVM `byte[]` / CLJS `Uint8Array`; the `codec` helpers convert.

### Noise XX transport

`org.replikativ.geheimnis.noise` implements the exact named Noise revision 34
suite `Noise_XX_25519_AESGCM_SHA256`. Create one state per connection with a
long-lived X25519 static keypair, then alternate `write-message` and
`read-message` according to XX's three-message handshake:

```text
initiator  -> e
responder  <- e, ee, s, es
initiator  -> s, se
```

Each operation returns a `core.async` channel containing its result or an
`ExceptionInfo`. Always replace a handshake or transport CipherState with the
returned next state; a state is deliberately single-use to prevent accidental
AES-GCM nonce reuse. `transport-ciphers` returns independent `:send` and
`:receive` states once both sides complete the handshake.

XX authenticates possession of the remote static X25519 key, not a user or
application identity by itself. Pin `remote-static-key` or bind it to the
application identity in an encrypted handshake payload before trusting the
peer. The initiator's first handshake payload is not encrypted. The `:prologue`
must be identical at both peers and should bind the carrier/application protocol
where appropriate.

Noise supplies messages, not stream framing. WebSocket message boundaries work
directly; byte-stream carriers must add an unambiguous length frame. Noise
messages are limited to 65,535 bytes.

## Development

```bash
# JVM
clojure -M:test -m kaocha.runner
# CLJS on Node
npx shadow-cljs compile node-test && node target/node-test.js
# format
clj -M:format   # check   ·   clj -M:ffix   # fix
```

## License

Copyright © 2016-2026 Christian Weilbach, Konrad Kühne

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this software except in compliance with the License. You may obtain a copy of
the License at http://www.apache.org/licenses/LICENSE-2.0. See `LICENSE` for
details.
