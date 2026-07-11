(ns org.replikativ.geheimnis.codec
  "Byte/text encodings for geheimnis v2 — base64url (JWT/JWK style, unpadded),
   hex, and UTF-8 string<->bytes. Pure and synchronous on both platforms.

   Byte convention across geheimnis v2: a `bytes` value is a JVM `byte[]` on CLJ
   and a `js/Uint8Array` on CLJS. These helpers convert to/from those."
  #?(:clj (:import [java.util Base64]
                   [java.nio.charset StandardCharsets])
     :cljs (:require [clojure.string :as str]
                     [goog.crypt :as gcrypt]
                     [goog.crypt.base64 :as gb64])))

;; ---------------------------------------------------------------------------
;; base64url — RFC 4648 §5, no padding (the JOSE/JWT/JWK alphabet)
;; ---------------------------------------------------------------------------

(defn bytes->b64url
  "Encode a byte-array to an unpadded base64url String."
  [bytes]
  #?(:clj  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) ^bytes bytes)
     ;; standard base64 then map to the url alphabet, strip padding — avoids the
     ;; finicky goog Alphabet enum and works across goog.crypt.base64 versions.
     :cljs (-> (gb64/encodeByteArray bytes)
               (str/replace "+" "-")
               (str/replace "/" "_")
               (str/replace "=" ""))))

(defn b64url->bytes
  "Decode a base64url String (padded or not) to a byte-array."
  [s]
  #?(:clj  (.decode (Base64/getUrlDecoder) ^String s)
     ;; goog's decoder accepts BOTH the standard and websafe alphabets, padded
     ;; or not, so a url-alphabet string decodes directly.
     :cljs (gb64/decodeStringToUint8Array s)))

;; ---------------------------------------------------------------------------
;; hex
;; ---------------------------------------------------------------------------

(defn bytes->hex
  "Lowercase hex String of a byte-array."
  [bytes]
  #?(:clj  (let [sb (StringBuilder.)]
             (doseq [b (seq bytes)]
               (.append sb (format "%02x" (bit-and b 0xff))))
             (.toString sb))
     :cljs (gcrypt/byteArrayToHex bytes)))

(defn hex->bytes
  "Byte-array of a hex String."
  [s]
  #?(:clj  (let [n (/ (count s) 2)
                 out (byte-array n)]
             (dotimes [i n]
               (aset out i (unchecked-byte
                            (Integer/parseInt (subs s (* 2 i) (+ 2 (* 2 i))) 16))))
             out)
     :cljs (js/Uint8Array. (gcrypt/hexToByteArray s))))

;; ---------------------------------------------------------------------------
;; UTF-8 text <-> bytes
;; ---------------------------------------------------------------------------

(defn str->bytes
  "UTF-8 bytes of a String."
  [s]
  #?(:clj  (.getBytes ^String s StandardCharsets/UTF_8)
     :cljs (js/Uint8Array. (gcrypt/stringToUtf8ByteArray s))))

(defn bytes->str
  "UTF-8 String of a byte-array."
  [bytes]
  #?(:clj  (String. ^bytes bytes StandardCharsets/UTF_8)
     :cljs (gcrypt/utf8ByteArrayToString bytes)))
