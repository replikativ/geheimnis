(ns org.replikativ.geheimnis.core
  "geheimnis v2 core: cryptographically-secure randomness and constant-time
   comparison — the two primitives every other module depends on.

   `random-bytes` is the ONLY sanctioned source of key/salt/nonce/IV material.
   It draws from a CSPRNG on both platforms (never Math.random). If no CSPRNG is
   available it throws loudly rather than degrading."
  #?(:clj (:import [java.security SecureRandom MessageDigest])))

;; ---------------------------------------------------------------------------
;; CSPRNG
;; ---------------------------------------------------------------------------

;; Loading/AOT-compiling this namespace must not capture a seeded RNG in a
;; native-image heap. Initialize on first use in the running process instead.
;; Delay preserves one thread-safe CSPRNG without allocating one per request.
#?(:clj (defonce ^:private secure-random (delay (SecureRandom.))))

#?(:cljs
   (defn- web-crypto []
     ;; browser: globalThis.crypto; Node >=19: global crypto; else fail loud.
     (or (when (exists? js/crypto) js/crypto)
         (when (exists? js/globalThis) (.-crypto js/globalThis))
         (throw (ex-info "No Web Crypto (crypto.getRandomValues) available — refusing to generate key material without a CSPRNG. On Node <19 expose globalThis.crypto = require('crypto').webcrypto."
                         {:platform :cljs})))))

(defn random-bytes
  "Return `n` cryptographically-random bytes (JVM byte[] / CLJS Uint8Array)."
  [n]
  #?(:clj  (let [b (byte-array n)] (.nextBytes ^SecureRandom @secure-random b) b)
     :cljs (let [b (js/Uint8Array. n)] (.getRandomValues (web-crypto) b) b)))

;; ---------------------------------------------------------------------------
;; constant-time comparison
;; ---------------------------------------------------------------------------

(defn ct-equal?
  "Constant-time byte-array equality — no early exit, so it doesn't leak where
   two MACs/tags/tokens first differ. (Length inequality is not itself secret.)"
  [a b]
  #?(:clj  (MessageDigest/isEqual ^bytes a ^bytes b)
     :cljs (let [la (.-length a) lb (.-length b)]
             (if (not= la lb)
               false
               (loop [i 0 acc 0]
                 (if (< i la)
                   (recur (inc i) (bit-or acc (bit-xor (aget a i) (aget b i))))
                   (zero? acc)))))))
