(ns org.replikativ.geheimnis.aead
  "AES-256-GCM authenticated encryption — the AEAD primitive for at-rest and
   in-transit confidentiality WITH integrity (a tampered ciphertext is rejected,
   unlike v1's unauthenticated CBC).

   ASYNC: every op returns a core.async channel yielding the result bytes, or an
   error value (an ExceptionInfo — konserve/superv `<?-` rethrows it). Web Crypto
   on CLJS is Promise-based; the JVM resolves synchronously into the channel. The
   contract is identical on both platforms.

   Conventions: 256-bit key (32 bytes), 96-bit nonce (12 bytes), 128-bit tag
   appended to the ciphertext (both JVM `AES/GCM/NoPadding` and Web Crypto lay the
   tag out the same way, so JVM↔CLJS ciphertext is interoperable). `aad` (bytes or
   nil) is authenticated-but-not-encrypted associated data — bind context (store
   key / version) into it so a blob can't be relocated and still verify."
  (:require [clojure.core.async :as a])
  #?(:clj (:import [javax.crypto Cipher]
                   [javax.crypto.spec SecretKeySpec GCMParameterSpec])))

(def tag-bits 128)

#?(:cljs
   (defn- subtle []
     (or (some-> (when (exists? js/crypto) js/crypto) .-subtle)
         (some-> (when (exists? js/globalThis) (.-crypto js/globalThis)) .-subtle)
         (throw (ex-info "No Web Crypto (crypto.subtle) available for AEAD" {})))))

#?(:clj
   (defn- jvm-gcm [mode ^bytes key ^bytes nonce aad ^bytes input]
     (let [c (Cipher/getInstance "AES/GCM/NoPadding")]
       (.init c (int mode) (SecretKeySpec. key "AES") (GCMParameterSpec. tag-bits nonce))
       (when aad (.updateAAD c ^bytes aad))
       (.doFinal c input))))

#?(:clj
   (defn- jvm->chan [f]
     (let [ch (a/chan 1)]
       (try (a/put! ch (f)) (catch Throwable e (a/put! ch e)))
       (a/close! ch)
       ch)))

#?(:cljs
   (defn- promise->chan [p]
     (let [ch (a/chan 1)]
       (.then p
              (fn [buf] (a/put! ch (js/Uint8Array. buf)) (a/close! ch))
              (fn [err] (a/put! ch (ex-info "AEAD operation failed (bad tag / key / nonce)"
                                            {:error err})) (a/close! ch)))
       ch)))

#?(:cljs
   (defn- cljs-gcm [op ^js key-bytes nonce aad input]
     ;; op is "encrypt" or "decrypt"; returns a channel of Uint8Array
     (promise->chan
      (-> (.importKey (subtle) "raw" key-bytes #js {:name "AES-GCM"} false #js [op])
          (.then (fn [k]
                   (let [params #js {:name "AES-GCM" :iv nonce :tagLength tag-bits}]
                     (when aad (set! (.-additionalData params) aad))
                     (if (= op "encrypt")
                       (.encrypt (subtle) params k input)
                       (.decrypt (subtle) params k input)))))))))

(defn aead-encrypt
  "Encrypt `plaintext` under AES-256-GCM. -> channel of (ciphertext ‖ 128-bit tag).
   `key` 32 bytes, `nonce` 12 bytes (unique per key!), `aad` bytes or nil."
  [key nonce aad plaintext]
  #?(:clj  (jvm->chan #(jvm-gcm Cipher/ENCRYPT_MODE key nonce aad plaintext))
     :cljs (cljs-gcm "encrypt" key nonce aad plaintext)))

(defn aead-decrypt
  "Decrypt `ciphertext` (ct ‖ tag) under AES-256-GCM. -> channel of plaintext, or
   an ExceptionInfo on the channel if the tag does not verify (tamper / wrong key
   / wrong nonce / wrong aad)."
  [key nonce aad ciphertext]
  #?(:clj  (jvm->chan #(jvm-gcm Cipher/DECRYPT_MODE key nonce aad ciphertext))
     :cljs (cljs-gcm "decrypt" key nonce aad ciphertext)))
