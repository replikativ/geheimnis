(ns org.replikativ.geheimnis.v2-aead-test
  "AES-256-GCM round-trip + authentication (tamper/wrong-key/wrong-aad rejection),
   async on both platforms."
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing async]])
            [clojure.core.async :as a]
            [org.replikativ.geheimnis.aead :as aead]
            [org.replikativ.geheimnis.core :as gc]
            [org.replikativ.geheimnis.codec :as codec]))

(defn- result-hex
  "hex of a byte-array result, or ::error if the op returned an error value."
  [r]
  (if #?(:clj (bytes? r) :cljs (instance? js/Uint8Array r))
    (codec/bytes->hex r)
    ::error))

(defn- flip-first [bs]
  #?(:clj  (let [c (java.util.Arrays/copyOf ^bytes bs (alength ^bytes bs))]
             (aset c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c)
     :cljs (let [c (.slice bs 0)] (aset c 0 (bit-xor (aget c 0) 1)) c)))

;; Deterministic AES-256-GCM vector (fixed key+nonce). A platform that both
;; PRODUCES and CONSUMES these exact bytes is byte-compatible with the other —
;; i.e. a JVM-encrypted konserve blob decrypts on a CLJS peer, and vice versa.
(def ^:private kat-key "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
(def ^:private kat-nonce "000102030405060708090a0b")
(def ^:private kat-aad "aad-ctx")
(def ^:private kat-pt "geheimnis-aead-kat")
(def ^:private kat-ct "2067be7eac88ac72fe6cf6eed08d5506e2a2b37b376771e4ea106c8999910c312857")

(deftest aead-interop-kat
  #?(:clj
     (let [k (codec/hex->bytes kat-key) n (codec/hex->bytes kat-nonce)
           aad (codec/str->bytes kat-aad) pt (codec/str->bytes kat-pt)]
       (is (= kat-ct (result-hex (a/<!! (aead/aead-encrypt k n aad pt)))) "encrypt -> fixed ct")
       (is (= kat-pt (codec/bytes->str (a/<!! (aead/aead-decrypt k n aad (codec/hex->bytes kat-ct))))) "decrypt(fixed ct) -> pt"))
     :cljs
     (cljs.test/async
      done
      (a/go
        (let [k (codec/hex->bytes kat-key) n (codec/hex->bytes kat-nonce)
              aad (codec/str->bytes kat-aad) pt (codec/str->bytes kat-pt)]
          (is (= kat-ct (result-hex (a/<! (aead/aead-encrypt k n aad pt)))) "encrypt -> fixed ct")
          (is (= kat-pt (codec/bytes->str (a/<! (aead/aead-decrypt k n aad (codec/hex->bytes kat-ct))))) "decrypt(fixed ct) -> pt")
          (done))))))

(deftest aead-roundtrip
  #?(:clj
     (let [key (gc/random-bytes 32) nonce (gc/random-bytes 12)
           aad (codec/str->bytes "ctx:v1") pt (codec/str->bytes "hello geheimnis aead 🔐")
           ct (a/<!! (aead/aead-encrypt key nonce aad pt))
           dec (a/<!! (aead/aead-decrypt key nonce aad ct))]
       (testing "decrypt(encrypt(x)) = x"
         (is (= (codec/bytes->hex pt) (result-hex dec))))
       (testing "a tampered ciphertext is rejected (GCM tag)"
         (is (= ::error (result-hex (a/<!! (aead/aead-decrypt key nonce aad (flip-first ct)))))))
       (testing "wrong key is rejected"
         (is (= ::error (result-hex (a/<!! (aead/aead-decrypt (gc/random-bytes 32) nonce aad ct))))))
       (testing "wrong aad is rejected"
         (is (= ::error (result-hex (a/<!! (aead/aead-decrypt key nonce (codec/str->bytes "ctx:v2") ct)))))))
     :cljs
     (cljs.test/async
      done
      (a/go
        (let [key (gc/random-bytes 32) nonce (gc/random-bytes 12)
              aad (codec/str->bytes "ctx:v1") pt (codec/str->bytes "hello geheimnis aead 🔐")
              ct (a/<! (aead/aead-encrypt key nonce aad pt))
              dec (a/<! (aead/aead-decrypt key nonce aad ct))]
          (is (= (codec/bytes->hex pt) (result-hex dec)) "round-trip")
          (is (= ::error (result-hex (a/<! (aead/aead-decrypt key nonce aad (flip-first ct))))) "tamper")
          (is (= ::error (result-hex (a/<! (aead/aead-decrypt (gc/random-bytes 32) nonce aad ct)))) "wrong key")
          (is (= ::error (result-hex (a/<! (aead/aead-decrypt key nonce (codec/str->bytes "ctx:v2") ct)))) "wrong aad")
          (done))))))
