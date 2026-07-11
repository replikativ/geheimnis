(ns org.replikativ.geheimnis.hash
  "Keyed hashing for geheimnis v2: HMAC-SHA-256 and HKDF-SHA-256 — synchronous on
   both platforms (goog.crypt.Hmac / javax.crypto.Mac). Raw (unkeyed) SHA digests
   are reused from hasch, not reimplemented: `sha256`/`sha512` are re-exported so
   callers have one hashing entry point. Staying synchronous here is deliberate —
   it keeps HS256 JWT verify sync in CLJS; only AEAD + the asymmetric curves need
   the async Web Crypto tier."
  (:require [hasch.core :as hasch]
            [org.replikativ.geheimnis.codec :as codec]
            #?@(:cljs [[goog.crypt.Hmac]
                       [goog.crypt.Sha256]]))
  #?(:clj (:import [javax.crypto Mac] [javax.crypto.spec SecretKeySpec])))

;; one hashing entry point — raw digests come from hasch (sync, portable)
(def sha256 hasch/sha256)
(def sha512 hasch/sha512)

(def ^:private sha256-hlen 32)
(def ^:private sha256-block 64)

(defn hmac-sha256
  "HMAC-SHA-256 of `msg` under `key` (both byte-arrays) -> byte-array."
  [key msg]
  #?(:clj  (let [m (Mac/getInstance "HmacSHA256")]
             (.init m (SecretKeySpec. ^bytes key "HmacSHA256"))
             (.doFinal m ^bytes msg))
     :cljs (let [h (goog.crypt.Hmac. (goog.crypt.Sha256.) key sha256-block)]
             (.update h msg)
             (js/Uint8Array. (.digest h)))))

(defn- byte-of [i]
  #?(:clj (byte-array [(unchecked-byte i)]) :cljs (js/Uint8Array. #js [i])))

(defn hkdf
  "HKDF-SHA-256 (RFC 5869): derive `len` bytes of key material from input keying
   material `ikm`, an optional `salt`, and context `info` (all byte-arrays;
   salt/info may be nil). -> byte-array of length `len`."
  [ikm salt info len]
  (let [salt (if (or (nil? salt) (zero? (codec/blen salt))) (codec/zeros sha256-hlen) salt)
        info (or info (codec/zeros 0))
        prk  (hmac-sha256 salt ikm)                       ; extract
        n    (long (Math/ceil (/ (double len) sha256-hlen)))]
    ;; expand: T(i) = HMAC(prk, T(i-1) || info || i); OKM = T(1)||…||T(n)[0:len]
    (loop [i 1, t (codec/zeros 0), acc []]
      (if (> i n)
        (codec/sub-bytes (codec/concat-bytes acc) len)
        (let [ti (hmac-sha256 prk (codec/concat-bytes [t info (byte-of i)]))]
          (recur (inc i) ti (conj acc ti)))))))
