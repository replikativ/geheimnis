(ns org.replikativ.geheimnis.sign
  "Ed25519 digital signatures — asymmetric authentication. A signer holds a
   private key; anyone with the matching public key can verify, with no shared
   secret. This is the primitive for peer-to-peer identity: peer A signs an
   assertion, peer B (browser, Node, or JVM) verifies it against A's public key.

   ASYNC: every op returns a core.async channel, exactly like `aead` — Web Crypto
   on ClojureScript is Promise-based, and the JVM resolves synchronously into the
   channel, so callers get one uniform contract on both platforms. `sign`/keygen
   yield byte-arrays; `verify` yields a boolean (or an ExceptionInfo on the
   channel if the key/signature is malformed).

   KEYS ARE RAW: a public key is 32 bytes, a private key is the 32-byte seed, a
   signature is 64 bytes — the encodings every Ed25519 implementation agrees on.
   Internally we wrap raw keys in the standard PKCS#8 / SPKI DER envelopes so the
   same bytes move between java.security and Web Crypto unchanged; a JVM-signed
   message verifies on a CLJS peer and vice versa (see sign-test's interop KAT).

   Platform note: Web Crypto reached Ed25519 in Chrome only in mid-2025, so a
   fallback is not hypothetical — an older browser fails outright. Call
   `set-fallback!` with a noble/ed25519 module and this uses it whenever Web
   Crypto cannot do the curve; require the npm package as usual and hand the
   module to `set-fallback!` at startup.

   Injected rather than required, so the dependency stays the consumer's choice
   and works in every build target — a dynamic `js/require` would not survive a
   browser build, and a static one would make ~4 KB mandatory for everybody.

   Historical note: Ed25519 in Web Crypto is available in Node 18+ and current
   browsers (2026). Very old browsers without it will surface an error on the
   channel; a `@noble/curves` fallback for that case is future work."
  (:require [clojure.core.async :as a]
            [org.replikativ.geheimnis.core :as gcore]
            [org.replikativ.geheimnis.codec :as codec])
  #?(:clj (:import [java.security KeyPairGenerator KeyFactory Signature]
                   [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec])))

;; Fixed DER envelopes for a raw Ed25519 seed / public key. The algorithm OID is
;; 1.3.101.112; the only variable part is the trailing 32 raw bytes, so these
;; constant prefixes are all we need to move between raw and PKCS8/SPKI.
(def ^:private pkcs8-prefix (codec/hex->bytes "302e020100300506032b657004220420"))
(def ^:private spki-prefix  (codec/hex->bytes "302a300506032b6570032100"))

(defn- seed->pkcs8 [seed] (codec/concat-bytes [pkcs8-prefix seed]))
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
         (throw (ex-info "No Web Crypto (crypto.subtle) available for Ed25519" {})))))

#?(:cljs (defonce ^:private fallback-impl (atom nil)))
#?(:cljs (defonce ^:private web-crypto-ok (atom nil)))

#?(:cljs
   (defn set-fallback!
     "Install a `@noble/ed25519`-shaped module for runtimes whose Web Crypto
      lacks Ed25519. Pass nil to clear."
     [m]
     (reset! fallback-impl m)))

#?(:cljs
   (defn- probe-web-crypto
     "Does this runtime's Web Crypto actually implement Ed25519?

      Presence of `crypto.subtle` is not the question — Chrome shipped subtle
      years before it shipped this curve — so the probe must ask for the
      algorithm, which is asynchronous. Cached after the first answer."
     []
     (let [ch (a/chan 1)]
       (if (some? @web-crypto-ok)
         (do (a/put! ch @web-crypto-ok) (a/close! ch))
         (try
           (-> (.generateKey (subtle) #js {:name "Ed25519"} true #js ["sign" "verify"])
               (.then (fn [_] (reset! web-crypto-ok true) (a/put! ch true) (a/close! ch))
                      (fn [_] (reset! web-crypto-ok false) (a/put! ch false) (a/close! ch))))
           (catch :default _
             (reset! web-crypto-ok false) (a/put! ch false) (a/close! ch))))
       ch)))

#?(:cljs
   (defn- bytes<-chan
     "Bridge a Promise<ArrayBuffer> to a channel of Uint8Array (error -> ex-info)."
     [p]
     (let [ch (a/chan 1)]
       (.then p
              (fn [buf] (a/put! ch (js/Uint8Array. buf)) (a/close! ch))
              (fn [err] (a/put! ch (ex-info "Ed25519 operation failed" {:error err})) (a/close! ch)))
       ch)))

#?(:clj
   (defn- jvm-generate []
     (let [kp (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))]
       {:public  (der->raw (.getEncoded (.getPublic kp)))
        :private (der->raw (.getEncoded (.getPrivate kp)))})))

#?(:clj
   (defn- jvm-priv [seed]
     (.generatePrivate (KeyFactory/getInstance "Ed25519")
                       (PKCS8EncodedKeySpec. (seed->pkcs8 seed)))))

#?(:clj
   (defn- jvm-pub [pub]
     (.generatePublic (KeyFactory/getInstance "Ed25519")
                      (X509EncodedKeySpec. (pub->spki pub)))))

#?(:clj
   (defn- jvm-sign [seed msg]
     (let [s (Signature/getInstance "Ed25519")]
       (.initSign s (jvm-priv seed)) (.update s ^bytes msg) (.sign s))))

#?(:clj
   (defn- jvm-verify [pub msg sig]
     (let [s (Signature/getInstance "Ed25519")]
       (.initVerify s (jvm-pub pub)) (.update s ^bytes msg) (.verify s ^bytes sig))))

#?(:cljs
   (defn- cljs-generate []
     (let [ch (a/chan 1)]
       (-> (.generateKey (subtle) #js {:name "Ed25519"} true #js ["sign" "verify"])
           (.then (fn [kp]
                    (js/Promise.all #js [(.exportKey (subtle) "spki" (.-publicKey kp))
                                         (.exportKey (subtle) "pkcs8" (.-privateKey kp))])))
           (.then (fn [arr]
                    (a/put! ch {:public  (der->raw (js/Uint8Array. (aget arr 0)))
                                :private (der->raw (js/Uint8Array. (aget arr 1)))})
                    (a/close! ch))
                  (fn [err] (a/put! ch (ex-info "Ed25519 keygen failed" {:error err})) (a/close! ch))))
       ch)))

#?(:cljs
   (defn- cljs-sign [seed msg]
     (bytes<-chan
      (-> (.importKey (subtle) "pkcs8" (seed->pkcs8 seed) #js {:name "Ed25519"} false #js ["sign"])
          (.then (fn [k] (.sign (subtle) #js {:name "Ed25519"} k msg)))))))

#?(:cljs
   (defn- cljs-verify [pub msg sig]
     (let [ch (a/chan 1)]
       (-> (.importKey (subtle) "spki" (pub->spki pub) #js {:name "Ed25519"} false #js ["verify"])
           (.then (fn [k] (.verify (subtle) #js {:name "Ed25519"} k sig msg)))
           (.then (fn [ok?] (a/put! ch (boolean ok?)) (a/close! ch))
                  (fn [err] (a/put! ch (ex-info "Ed25519 verify failed" {:error err})) (a/close! ch))))
       ch)))

#?(:cljs
   (defn- noble-generate [m]
     (let [ch (a/chan 1)
           seed (gcore/random-bytes 32)]
       ;; ^js on the injected module: it is an opaque foreign object, so without
       ;; the hint :advanced would rename these methods and the fallback would
       ;; break only in a release build.
       (-> (.getPublicKeyAsync ^js m seed)
           (.then (fn [pub] (a/put! ch {:public pub :private seed}) (a/close! ch))
                  (fn [err] (a/put! ch (ex-info "Ed25519 keygen failed" {:error err}))
                    (a/close! ch))))
       ch)))

#?(:cljs
   (defn- dispatch
     "Web Crypto when it implements the curve, the injected fallback otherwise."
     [web-fn fallback-fn]
     (let [ch (a/chan 1)]
       (a/go
         (let [m @fallback-impl]
           (if (and m (not (a/<! (probe-web-crypto))))
             (a/pipe (fallback-fn m) ch)
             (a/pipe (web-fn) ch))))
       ch)))

(defn generate-keypair
  "Generate a fresh Ed25519 keypair. -> channel of {:public <32 bytes>
   :private <32-byte seed>}."
  []
  #?(:clj (jvm->chan jvm-generate)
     :cljs (dispatch cljs-generate noble-generate)))

(defn sign
  "Sign `message` (bytes) with a 32-byte Ed25519 `private-key` seed.
   -> channel of the 64-byte signature. Ed25519 is deterministic: the same
   (seed, message) always yields the same signature on every platform."
  [private-key message]
  #?(:clj  (jvm->chan #(jvm-sign private-key message))
     :cljs (dispatch #(cljs-sign private-key message)
                     (fn [m] (bytes<-chan (.signAsync ^js m message private-key))))))

(defn verify
  "Verify `signature` over `message` (bytes) against a 32-byte Ed25519
   `public-key`. -> channel of true/false, or an ExceptionInfo on the channel if
   the key or signature is malformed."
  [public-key message signature]
  #?(:clj  (jvm->chan #(jvm-verify public-key message signature))
     :cljs (dispatch #(cljs-verify public-key message signature)
                     (fn [m]
                       (let [ch (a/chan 1)]
                         (-> (.verifyAsync ^js m signature message public-key)
                             (.then (fn [ok?] (a/put! ch (boolean ok?)) (a/close! ch))
                                    (fn [_] (a/put! ch false) (a/close! ch))))
                         ch)))))
