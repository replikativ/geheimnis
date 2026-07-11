(ns org.replikativ.geheimnis.dh
  "X25519 Diffie-Hellman key agreement — the confidentiality counterpart to
   `sign`. Two peers each hold a keypair; from opposite halves they compute the
   SAME 32-byte shared secret, and nothing secret ever crosses the wire — only
   public keys. This is how two peers (or a sender and a recipient) establish an
   encryption key with no pre-shared secret, so a relay/server can carry
   ciphertext it cannot read.

   The raw shared secret is NOT used directly as a key — run it through
   `hkdf` (org.replikativ.geheimnis.hash) to derive an AEAD key, then encrypt
   with `aead`. dh establishes the key; hkdf shapes it; aead uses it.

   ASYNC + RAW KEYS, exactly like `sign`: every op returns a core.async channel;
   a public key is 32 bytes, a private key is the 32-byte scalar, and the shared
   secret is 32 bytes. Internally we wrap raw keys in the standard PKCS#8 / SPKI
   DER envelopes (X25519 OID 1.3.101.110) so the same bytes move between
   java.security and Web Crypto unchanged — a JVM peer and a CLJS peer derive the
   identical secret (see dh-test's interop KAT).

   Platform note: X25519 in Web Crypto is available in Node 18+ and current
   browsers; the JVM uses java.security KeyAgreement (JDK 11+)."
  (:require [clojure.core.async :as a]
            [org.replikativ.geheimnis.codec :as codec])
  #?(:clj (:import [java.security KeyPairGenerator KeyFactory]
                   [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
                   [javax.crypto KeyAgreement])))

;; Fixed DER envelopes for a raw X25519 scalar / public key. Same structure as
;; Ed25519 but with the X25519 algorithm OID (1.3.101.110 = ...2b656e), so the
;; only difference from sign's prefixes is that trailing OID byte (6e vs 70).
(def ^:private pkcs8-prefix (codec/hex->bytes "302e020100300506032b656e04220420"))
(def ^:private spki-prefix  (codec/hex->bytes "302a300506032b656e032100"))

(defn- scalar->pkcs8 [scalar] (codec/concat-bytes [pkcs8-prefix scalar]))
(defn- pub->spki [pub] (codec/concat-bytes [spki-prefix pub]))

(defn- der->raw
  "Last 32 bytes of a PKCS8/SPKI DER encoding — the raw key material."
  [der]
  (let [n (codec/blen der)]
    #?(:clj  (java.util.Arrays/copyOfRange ^bytes der (- n 32) n)
       :cljs (.slice der (- n 32)))))

#?(:clj
   (defn- jvm->chan [f]
     (let [ch (a/chan 1)]
       (try (a/put! ch (f)) (catch Throwable e (a/put! ch e)))
       (a/close! ch)
       ch)))

#?(:cljs
   (defn- subtle []
     (or (some-> (when (exists? js/crypto) js/crypto) .-subtle)
         (some-> (when (exists? js/globalThis) (.-crypto js/globalThis)) .-subtle)
         (throw (ex-info "No Web Crypto (crypto.subtle) available for X25519" {})))))

#?(:clj
   (defn- jvm-generate []
     (let [kp (.generateKeyPair (KeyPairGenerator/getInstance "X25519"))]
       {:public  (der->raw (.getEncoded (.getPublic kp)))
        :private (der->raw (.getEncoded (.getPrivate kp)))})))

#?(:clj
   (defn- jvm-priv [scalar]
     (.generatePrivate (KeyFactory/getInstance "X25519")
                       (PKCS8EncodedKeySpec. (scalar->pkcs8 scalar)))))

#?(:clj
   (defn- jvm-pub [pub]
     (.generatePublic (KeyFactory/getInstance "X25519")
                      (X509EncodedKeySpec. (pub->spki pub)))))

#?(:clj
   (defn- jvm-agree [scalar pub]
     (let [ka (KeyAgreement/getInstance "X25519")]
       (.init ka (jvm-priv scalar))
       (.doPhase ka (jvm-pub pub) true)
       (.generateSecret ka))))

#?(:cljs
   (defn- cljs-generate []
     (let [ch (a/chan 1)]
       (-> (.generateKey (subtle) #js {:name "X25519"} true #js ["deriveBits"])
           (.then (fn [kp]
                    (js/Promise.all #js [(.exportKey (subtle) "spki" (.-publicKey kp))
                                         (.exportKey (subtle) "pkcs8" (.-privateKey kp))])))
           (.then (fn [arr]
                    (a/put! ch {:public  (der->raw (js/Uint8Array. (aget arr 0)))
                                :private (der->raw (js/Uint8Array. (aget arr 1)))})
                    (a/close! ch))
                  (fn [err] (a/put! ch (ex-info "X25519 keygen failed" {:error err})) (a/close! ch))))
       ch)))

#?(:cljs
   (defn- cljs-agree [scalar pub]
     (let [ch (a/chan 1)]
       (-> (js/Promise.all
            #js [(.importKey (subtle) "pkcs8" (scalar->pkcs8 scalar) #js {:name "X25519"} false #js ["deriveBits"])
                 (.importKey (subtle) "spki" (pub->spki pub) #js {:name "X25519"} false #js [])])
           (.then (fn [ks]
                    (.deriveBits (subtle) #js {:name "X25519" :public (aget ks 1)} (aget ks 0) 256)))
           (.then (fn [buf] (a/put! ch (js/Uint8Array. buf)) (a/close! ch))
                  (fn [err] (a/put! ch (ex-info "X25519 key agreement failed" {:error err})) (a/close! ch))))
       ch)))

(defn generate-keypair
  "Generate a fresh X25519 keypair. -> channel of {:public <32 bytes>
   :private <32-byte scalar>}."
  []
  #?(:clj (jvm->chan jvm-generate) :cljs (cljs-generate)))

(defn key-agreement
  "Derive the shared secret from your 32-byte `private-key` scalar and the peer's
   32-byte `public-key`. -> channel of the 32-byte shared secret. Both peers get
   the SAME secret from opposite halves. Do NOT use the raw output as a key —
   feed it through `hkdf` to derive an AEAD key."
  [private-key public-key]
  #?(:clj  (jvm->chan #(jvm-agree private-key public-key))
     :cljs (cljs-agree private-key public-key)))
